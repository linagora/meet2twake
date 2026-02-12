package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "time/tzdata"

	"github.com/gofrs/uuid/v5"
	pgxfrs "github.com/jackc/pgx-gofrs-uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/otiai10/openaigo"
	"github.com/wneessen/go-mail"
)

var clouderyURL, clouderyToken string
var minioClient *minio.Client
var mailFrom, mailSMTP string
var mailPort int
var mailTLSPolicy mail.TLSPolicy
var aiClient *openaigo.Client
var aiModel string

func main() {
	debug := false
	switch strings.ToLower(os.Getenv("LOG_LEVEL")) {
	case "debug":
		debug = true
		slog.SetLogLoggerLevel(slog.LevelDebug)
	case "warn":
		slog.SetLogLoggerLevel(slog.LevelWarn)
	case "error":
		slog.SetLogLoggerLevel(slog.LevelError)
	default:
		slog.SetLogLoggerLevel(slog.LevelInfo)
	}

	port := 8090
	if env := os.Getenv("PORT"); env != "" {
		p, err := strconv.Atoi(env)
		if err != nil {
			slog.Error("Failed to parse the PORT", "error", err)
			os.Exit(1)
		}
		port = p
	}

	clouderyURL = "https://manager.cozycloud.cc/"
	if u := os.Getenv("CLOUDERY_URL"); u != "" {
		clouderyURL = u
	}
	clouderyToken = os.Getenv("CLOUDERY_TOKEN")
	if clouderyToken == "" {
		slog.Error("Missing CLOUDERY_TOKEN")
		os.Exit(1)
	}

	mailFrom = "noreply@linagora.com"
	if from := os.Getenv("MAIL_FROM"); from != "" {
		mailFrom = from
	}
	mailSMTP = "smtp.linagora.com"
	if smtp := os.Getenv("MAIL_SMTP"); smtp != "" {
		mailSMTP = smtp
	}
	mailPort = 25
	if env := os.Getenv("MAIL_PORT"); env != "" {
		p, err := strconv.Atoi(env)
		if err != nil {
			slog.Error("Failed to parse the MAIL_PORT", "error", err)
			os.Exit(1)
		}
		mailPort = p
	}
	mailTLSPolicy = mail.TLSMandatory
	if disable := os.Getenv("MAIL_DISABLE_TLS"); disable != "" {
		noTLS, err := strconv.ParseBool(disable)
		if err != nil {
			slog.Error("Invalid MAIL_DISABLE_TLS", "error", err)
			os.Exit(1)
		}
		if noTLS {
			mailTLSPolicy = mail.NoTLS
		}
	}

	aiAPIKey := os.Getenv("AI_API_KEY")
	aiBaseURL := os.Getenv("AI_BASE_URL")
	aiModel = os.Getenv("AI_MODEL")
	if aiAPIKey == "" || aiBaseURL == "" || aiModel == "" {
		slog.Error("AI_API_KEY, AI_BASE_URL and AI_MODEL must be defined")
		os.Exit(1)
	}
	aiClient = openaigo.NewClient(aiAPIKey)
	aiClient.BaseURL = aiBaseURL

	prepareMinIOClient(debug)

	token := os.Getenv("TOKEN")
	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/minio", withAuth(minioHandler, token))
	mux.HandleFunc("/transcript", withAuth(transcriptHandler, token))

	handler := withLog(mux)

	log.Printf("Starting server on port %d...", port)
	if err := http.ListenAndServe(fmt.Sprintf(":%d", port), handler); err != nil {
		slog.Error("Server failed to start", "error", err)
		os.Exit(1)
	}
}

func prepareMinIOClient(debug bool) {
	minioURL := os.Getenv("MINIO_URL")
	minioUser := os.Getenv("MINIO_USER")
	minioPassword := os.Getenv("MINIO_PASSWORD")
	minioInsecure := os.Getenv("MINIO_INSECURE")
	minioUseSSL := os.Getenv("MINIO_USE_SSL")

	if minioURL == "" || minioUser == "" || minioPassword == "" {
		slog.Error("MINIO_URL, MINIO_USER and MINIO_PASSWORD must be defined")
		os.Exit(1)
	}
	u, err := url.Parse(minioURL)
	if err != nil {
		slog.Error("Invalid MINIO_URL", "error", err)
		os.Exit(1)
	}

	useSSL := true
	if minioUseSSL != "" {
		ssl, err := strconv.ParseBool(minioUseSSL)
		if err != nil {
			slog.Error("Invalid MINIO_USE_SSL", "error", err)
			os.Exit(1)
		}
		useSSL = ssl
	}

	skipVerify := false
	if minioInsecure != "" {
		insecure, err := strconv.ParseBool(minioInsecure)
		if err != nil {
			slog.Error("Invalid MINIO_INSECURE", "error", err)
			os.Exit(1)
		}
		skipVerify = insecure
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: skipVerify},
	}

	client, err := minio.New(u.Host, &minio.Options{
		Creds:     credentials.NewStaticV4(minioUser, minioPassword, ""),
		Secure:    useSSL,
		Transport: transport,
	})
	if err != nil {
		slog.Error("Erreur lors de la création du client MinIO", "error", err)
	}
	minioClient = client

	if debug {
		client.TraceOn(os.Stderr)
	}
}

func withAuth(next http.HandlerFunc, token string) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token != "" {
			auth := r.Header.Get("Authorization")
			if auth == "" {
				sendError(http.StatusUnauthorized, w, errors.New("missing Authorization header"))
				return
			}
			auth = strings.TrimPrefix(auth, "Bearer ")
			if auth != token {
				sendError(http.StatusForbidden, w, errors.New("invalid Authorization header"))
				return
			}
		}

		next(w, r)
	})
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func withLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(wrapped, r)
		slog.Info("Request",
			"status", wrapped.statusCode,
			"method", r.Method,
			"path", r.URL.Path,
			"duration", time.Since(start),
		)
	})
}

func sendError(code int, res http.ResponseWriter, err error) {
	res.WriteHeader(code)
	fmt.Printf("Error: %s\n", err)
	slog.Warn("Error", "error", err)
}

func healthHandler(res http.ResponseWriter, req *http.Request) {
	fmt.Fprintln(res, `{"status": "ok"}`)
}

type webhookRequest struct {
	EventName string
	Key       string
}

func minioHandler(res http.ResponseWriter, req *http.Request) {
	var webhook webhookRequest
	if err := json.NewDecoder(req.Body).Decode(&webhook); err != nil {
		sendError(http.StatusBadRequest, res, err)
		return
	}
	if webhook.EventName != "s3:ObjectCreated:Put" || !strings.HasSuffix(webhook.Key, ".json") {
		res.WriteHeader(http.StatusNoContent)
		return
	}

	_, startedAt, err := getRoomIDAndStartedAt(webhook.Key)
	if err != nil {
		sendError(http.StatusInternalServerError, res, err)
		return
	}

	key := strings.TrimSuffix(webhook.Key, ".json")
	recordingIDStr := strings.SplitN(filepath.Base(key), ".", 2)[0]
	recordingID, err := uuid.FromString(recordingIDStr)
	if err != nil {
		sendError(http.StatusInternalServerError, res, fmt.Errorf("invalid recording UUID: %w", err))
		return
	}

	sub, email, err := getSubFromRecordingID(recordingID)
	if err != nil {
		sendError(http.StatusInternalServerError, res, err)
		return
	}

	if email == "" {
		slog.Warn("No email found for user", "sub", sub, "recordingID", recordingID.String())
	}

	instance, err := findInstanceBySub(sub)
	if err != nil {
		sendError(http.StatusInternalServerError, res, err)
		return
	}

	token, err := getDriveToken(instance)
	if err != nil {
		sendError(http.StatusInternalServerError, res, err)
		return
	}
	content, err := getFromMinIO(key)
	if err != nil {
		sendError(http.StatusInternalServerError, res, err)
		return
	}
	defer content.Close()

	dirID, err := saveContent(instance, token, filepath.Base(key), startedAt, content)
	if err != nil {
		sendError(http.StatusInternalServerError, res, err)
		return
	}

	slog.Info("recording saved", "sub", sub)

	// Only send email for .mp4 recordings, not .ogg files
	// .ogg files are part of the transcription workflow and will receive email from transcriptHandler
	if email != "" && strings.Contains(key, ".mp4") {
		if err := sendEmail(email, instance, dirID); err != nil {
			slog.Warn("Cannot send email", "err", err, "recipient", email, "instance", instance)
		} else {
			slog.Info("email sent", "recipient", email, "instance", instance)
		}
	}

	res.WriteHeader(http.StatusNoContent)
}

type recordingJSON struct {
	RoomName  string `json:"room_name"`
	StartedAt int64  `json:"started_at"`
}

func getRoomIDAndStartedAt(key string) (*uuid.UUID, *time.Time, error) {
	obj, err := getFromMinIO(key)
	if err != nil {
		return nil, nil, err
	}
	defer obj.Close()
	var data recordingJSON
	if err := json.NewDecoder(obj).Decode(&data); err != nil {
		return nil, nil, err
	}
	// The actual UUID is in room_name, not room_id
	slog.Debug("getRoomID",
		"room_name", data.RoomName,
		"started_at", data.StartedAt,
	)
	id, err := uuid.FromString(data.RoomName)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid room_name UUID: %w", err)
	}
	startedAt := time.UnixMicro(data.StartedAt / 1000)
	loc, err := time.LoadLocation("Europe/Paris")
	if err == nil {
		startedAt = startedAt.In(loc)
	} else {
		slog.Warn("Cannot load Paris timezone", "error", err)
	}
	return &id, &startedAt, nil
}

func getFromMinIO(key string) (*minio.Object, error) {
	ctx := context.Background()
	parts := strings.SplitN(key, "/", 2)
	bucket := parts[0]
	objectName := parts[1]
	slog.Debug("getFromMinIO",
		"bucket", bucket,
		"objectName", objectName)
	obj, err := minioClient.GetObject(ctx, bucket, objectName, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("Cannot get from minIO: %s", err)
	}
	return obj, nil
}

const query = `
SELECT u.sub, u.email
FROM meet_user u
JOIN meet_recording_access ra ON u.id = ra.user_id
WHERE ra.recording_id = $1
  AND ra.role = 'owner';
`

func getPostgresURL() string {
	// If POSTGRES_URL is defined, use it directly (backward compatibility)
	if pgURL := os.Getenv("POSTGRES_URL"); pgURL != "" {
		return pgURL
	}

	// Otherwise, build the URL from components
	host := os.Getenv("POSTGRES_HOST")
	port := os.Getenv("POSTGRES_PORT")
	user := os.Getenv("POSTGRES_USER")
	password := os.Getenv("POSTGRES_PASSWORD")
	database := os.Getenv("POSTGRES_DB")
	sslmode := os.Getenv("POSTGRES_SSLMODE")

	if host == "" || user == "" || password == "" || database == "" {
		log.Fatal("POSTGRES_HOST, POSTGRES_USER, POSTGRES_PASSWORD and POSTGRES_DB must be defined")
	}

	if port == "" {
		port = "5432"
	}
	if sslmode == "" {
		sslmode = "require"
	}

	// Encode user and password for the URL
	userEncoded := url.QueryEscape(user)
	passwordEncoded := url.QueryEscape(password)

	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s",
		userEncoded, passwordEncoded, host, port, database, sslmode)
}

func getSubFromRecordingID(recordingID uuid.UUID) (string, string, error) {
	ctx := context.Background()
	config, err := pgxpool.ParseConfig(getPostgresURL())
	if err != nil {
		return "", "", fmt.Errorf("Cannot parse PG config: %s", err)
	}

	config.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		pgxfrs.Register(conn.TypeMap())
		return nil
	}

	conn, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return "", "", fmt.Errorf("Cannot connect to PG: %s", err)
	}
	defer conn.Close()

	var sub string
	var email *string
	err = conn.QueryRow(context.Background(), query, recordingID).Scan(&sub, &email)
	if err != nil {
		return "", "", fmt.Errorf("Cannot query: %s", err)
	}

	emailValue := ""
	if email != nil {
		emailValue = *email
	}

	slog.Debug("getSubFromRecordingID",
		"recordingID", recordingID.String(),
		"sub", sub,
		"email", emailValue)
	return sub, emailValue, nil
}

func saveContent(instance, token, filename string, startedAt *time.Time, content *minio.Object) (string, error) {
	dirname := "Reunion_" + startedAt.Format("02-01-2006_15-04")
	meetingDirID, err := ensureMeetingDirectory(instance, token, dirname)
	if err != nil {
		return "", fmt.Errorf("cannot create directory in drive: %w", err)
	}

	// dirID is used for saving the file
	dirID := meetingDirID

	// For .ogg files, save them in Inbox folder
	if strings.Contains(filename, ".ogg") {
		inboxID, err := ensureInboxDirectory(instance, token)
		if err != nil {
			return "", fmt.Errorf("cannot create inbox directory: %w", err)
		}
		filename = "Réunion_" + startedAt.Format("02-01-2006_15-04") + ".ogg"
		dirID = inboxID
	} else if strings.Contains(filename, ".mp4") {
		filename = "recording-" + filename
	}
	q := &url.Values{}
	q.Add("Type", "file")
	q.Add("Name", filename)
	if info, err := content.Stat(); err == nil {
		q.Add("Content-Length", fmt.Sprintf("%d", info.Size))
	}
	u := &url.URL{
		Scheme:   "https",
		Host:     instance,
		Path:     "/files/" + dirID,
		RawQuery: q.Encode(),
	}
	req, err := http.NewRequest(http.MethodPost, u.String(), content)
	if err != nil {
		return "", fmt.Errorf("cannot make request to stack: %w", err)
	}
	req.Header.Add("Authorization", "Bearer "+token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("cannot call stack: %w", err)
	}
	slog.Debug("Save recording",
		"instance", instance,
		"name", filename,
		"status", res.StatusCode)
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("unexpected response from the stack: %d", res.StatusCode)
	}
	// Always return meeting directory ID for email link, even if file was saved in Inbox
	return meetingDirID, nil
}

const meetingsDirName = "_Reunions"

func ensureMeetingDirectory(instance, token, dirname string) (string, error) {
	meetingsDirID, err := ensureDirectory(instance, token, "/"+meetingsDirName, "io.cozy.files.root-dir", true)
	if err != nil {
		return "", err
	}
	return ensureDirectory(instance, token, "/"+meetingsDirName+"/"+dirname, meetingsDirID, false)
}

func ensureInboxDirectory(instance, token string) (string, error) {
	meetingsDirID, err := ensureDirectory(instance, token, "/"+meetingsDirName, "io.cozy.files.root-dir", true)
	if err != nil {
		return "", err
	}
	return ensureDirectory(instance, token, "/"+meetingsDirName+"/Inbox", meetingsDirID, false)
}

func ensureDirectory(instance, token, path, parentID string, favorite bool) (string, error) {
	dirID, err := getDirID(instance, token, path)
	if err != nil {
		return "", err
	}
	if dirID != "" {
		return dirID, nil
	}
	dirID, err = createDirectory(instance, token, filepath.Base(path), parentID)
	if err != nil {
		return "", err
	}
	if favorite {
		if err := putInFavorite(instance, token, dirID); err != nil {
			slog.Warn("cannot put in favorite", "error", err)
		}
	}
	return dirID, nil
}

type stackFile struct {
	Data struct {
		ID string `json:"id"`
	} `json:"data"`
}

func getDirID(instance, token, path string) (string, error) {
	q := &url.Values{}
	q.Add("Path", path)
	u := &url.URL{
		Scheme:   "https",
		Host:     instance,
		Path:     "/files/metadata",
		RawQuery: q.Encode(),
	}
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("cannot make request to stack: %w", err)
	}
	req.Header.Add("Authorization", "Bearer "+token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("cannot call stack: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNotFound {
		return "", nil
	}
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected response from the stack: %d", res.StatusCode)
	}
	var file stackFile
	if err := json.NewDecoder(res.Body).Decode(&file); err != nil {
		return "", fmt.Errorf("cannot parse the response from the stack: %w", err)
	}
	return file.Data.ID, nil
}

func createDirectory(instance, token, dirname, parentID string) (string, error) {
	q := &url.Values{}
	q.Add("Type", "directory")
	q.Add("Name", dirname)
	u := &url.URL{
		Scheme:   "https",
		Host:     instance,
		Path:     "/files/" + parentID,
		RawQuery: q.Encode(),
	}
	req, err := http.NewRequest(http.MethodPost, u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("cannot make request to stack: %w", err)
	}
	req.Header.Add("Authorization", "Bearer "+token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("cannot call stack: %w", err)
	}
	slog.Debug("Create directory",
		"instance", instance,
		"name", dirname,
		"status", res.StatusCode)
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("unexpected response from the stack: %d", res.StatusCode)
	}
	var file stackFile
	if err := json.NewDecoder(res.Body).Decode(&file); err != nil {
		return "", fmt.Errorf("cannot parse the response from the stack: %w", err)
	}
	return file.Data.ID, nil
}

func putInFavorite(instance, token, dirID string) error {
	u := &url.URL{
		Scheme: "https",
		Host:   instance,
		Path:   "/files/" + dirID,
	}
	buf, err := json.Marshal(map[string]any{
		"data": map[string]any{
			"type": "io.cozy.files",
			"id":   dirID,
			"attributes": map[string]any{
				"cozyMetadata": map[string]any{
					"favorite": true,
				},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("cannot marshal request body: %w", err)
	}
	body := bytes.NewReader(buf)
	req, err := http.NewRequest(http.MethodPatch, u.String(), body)
	if err != nil {
		return fmt.Errorf("cannot make request to stack: %w", err)
	}
	req.Header.Add("Authorization", "Bearer "+token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("cannot call stack: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected response from the stack: %d", res.StatusCode)
	}
	return nil
}

type transcriptRequest struct {
	Title   string `json:"title"`
	Content string `json:"content"`
	Email   string `json:"email"`
	Sub     string `json:"sub"`
}

func transcriptHandler(res http.ResponseWriter, req *http.Request) {
	var transcript transcriptRequest
	if err := json.NewDecoder(req.Body).Decode(&transcript); err != nil {
		sendError(http.StatusBadRequest, res, err)
		return
	}

	instance, err := findInstanceBySub(transcript.Sub)
	if err != nil {
		sendError(http.StatusInternalServerError, res, err)
		return
	}

	token, err := getDriveToken(instance)
	if err != nil {
		sendError(http.StatusInternalServerError, res, err)
		return
	}

	dirID, err := saveTranscript(instance, token, transcript)
	if err != nil {
		sendError(http.StatusInternalServerError, res, err)
		return
	}
	slog.Info("transcript saved", "sub", transcript.Sub)

	summary, err := generateSummary(transcript.Content)
	if err == nil {
		err = saveSummary(instance, token, summary, dirID)
	}
	if err != nil {
		slog.Warn("Cannot generate summary", "err", err)
	}

	if err := sendEmail(transcript.Email, instance, dirID); err != nil {
		slog.Warn("Cannot send email", "err", err, "recipient", transcript.Email, "instance", instance)
	} else {
		slog.Info("email sent", "recipient", transcript.Email, "instance", instance)
	}

	res.WriteHeader(http.StatusNoContent)
}

func findInstanceBySub(sub string) (string, error) {
	instance := fmt.Sprintf("%s.twake.linagora.com", sub)
	return instance, nil
}

type driveTokenResponse struct {
	Token string `json:"token"`
}

func getDriveToken(instance string) (string, error) {
	u, err := url.Parse(clouderyURL)
	if err != nil {
		return "", fmt.Errorf("invalid clouderyURL: %w", err)
	}
	u.Path = "/api/public/instances/" + instance + "/drive_token"
	req, err := http.NewRequest(http.MethodPost, u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("cannot make request to cloudery: %w", err)
	}
	req.Header.Add("Authorization", "Bearer "+clouderyToken)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("cannot call cloudery: %w", err)
	}
	slog.Debug("Get token for",
		"instance", instance,
		"status", res.StatusCode)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected response from the cloudery: %d", res.StatusCode)
	}
	var body driveTokenResponse
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("unexpected response from the cloudery: %w", err)
	}
	return body.Token, nil
}

const promptTLDR = `
Tu es un agent dont le rôle est de créer un TL;DR (résumé très concis) d'un compte rendu de réunion. Tu utiliseras un style synthétique, administratif, à la troisième personne, sans affect. Tu recevras en entrée le transcript. Ta tâche est de rédiger un résumé concis et structuré, en te concentrant uniquement sur les informations essentielles et pertinentes. Tu répondras en un paragraphe structuré (3 à 6 phrases), sans rien ajouter d'autre. Tu répondras dans le format suivant sans rien ajouter d'autre:
### Résumé TL;DR
[Résumé concis et structuré]
`

func generateSummary(content string) (string, error) {
	request := openaigo.ChatRequest{
		Model: aiModel,
		Messages: []openaigo.Message{
			{Role: "system", Content: promptTLDR},
			{Role: "user", Content: content},
		},
	}
	ctx := context.Background()
	response, err := aiClient.Chat(ctx, request)
	if err != nil {
		return "", fmt.Errorf("AI error: %w", err)
	}
	if len(response.Choices) == 0 {
		return "", fmt.Errorf("AI error: no response")
	}
	fmt.Printf("response = %#v\n", response)
	return response.Choices[0].Message.Content, nil
}

func saveTranscript(instance, token string, transcript transcriptRequest) (string, error) {
	parts := strings.Split(transcript.Title, " du ")
	name := parts[len(parts)-1]

	// Parse the date in format "2006-01-02 à 15:04" and reformat to "Reunion_02-01-2006_15-04"
	loc, _ := time.LoadLocation("Europe/Paris")
	parsedTime, err := time.ParseInLocation("2006-01-02 à 15:04", name, loc)
	if err != nil {
		return "", fmt.Errorf("cannot parse date from title: %w", err)
	}
	dirname := "Reunion_" + parsedTime.Format("02-01-2006_15-04")

	dirID, err := ensureMeetingDirectory(instance, token, dirname)
	if err != nil {
		return "", err
	}

	q := &url.Values{}
	q.Add("Type", "file")
	q.Add("Name", "Transcription_"+parsedTime.Format("02-01-2006_15-04")+".cozy-note")
	q.Add("Content-Type", "text/vnd.cozy.note+markdown")
	u := &url.URL{
		Scheme:   "https",
		Host:     instance,
		Path:     "/files/" + dirID,
		RawQuery: q.Encode(),
	}
	body := strings.NewReader(transcript.Content)
	req, err := http.NewRequest(http.MethodPost, u.String(), body)
	if err != nil {
		return "", fmt.Errorf("cannot make request to stack: %w", err)
	}
	req.Header.Add("Authorization", "Bearer "+token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("cannot call stack: %w", err)
	}
	slog.Debug("Save transcript",
		"instance", instance,
		"name", transcript.Title,
		"status", res.StatusCode)
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("unexpected response from the stack: %d", res.StatusCode)
	}
	return dirID, nil
}

func saveSummary(instance, token, summary, dirID string) error {
	q := &url.Values{}
	q.Add("Type", "file")
	q.Add("Name", "Résumé.cozy-note")
	q.Add("Content-Type", "text/vnd.cozy.note+markdown")
	u := &url.URL{
		Scheme:   "https",
		Host:     instance,
		Path:     "/files/" + dirID,
		RawQuery: q.Encode(),
	}
	body := strings.NewReader(summary)
	req, err := http.NewRequest(http.MethodPost, u.String(), body)
	if err != nil {
		return fmt.Errorf("cannot make request to stack: %w", err)
	}
	req.Header.Add("Authorization", "Bearer "+token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("cannot call stack: %w", err)
	}
	slog.Debug("Save summary",
		"instance", instance,
		"status", res.StatusCode)
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		return fmt.Errorf("unexpected response from the stack: %d", res.StatusCode)
	}
	return nil
}

func sendEmail(recipient, instance, dirID string) error {
	title := "Un enregistrement est disponible dans votre Twake Drive"
	text := `Vous pouvez dès à présent retrouver les fichiers liés à votre réunion dans votre Twake Drive.`
	parts := strings.Split(instance, ".")
	parts[0] += "-drive"
	link := fmt.Sprintf("https://%s/#/folder/%s", strings.Join(parts, "."), dirID)
	tmpl := template.Must(template.New("email").Parse(emailTemplate))
	buf := new(bytes.Buffer)
	if err := tmpl.Execute(buf, map[string]any{"Title": title, "Text": text, "Link": link}); err != nil {
		return fmt.Errorf("cannot execute email template: %w", err)
	}
	html := buf.String()
	text += "\n\n" + link

	message := mail.NewMsg()
	if err := message.From(mailFrom); err != nil {
		return err
	}
	if err := message.To(recipient); err != nil {
		return err
	}
	message.Subject(title)
	message.SetBodyString(mail.TypeTextPlain, text)
	message.SetBodyString(mail.TypeTextHTML, html)
	client, err := mail.NewClient(mailSMTP, mail.WithPort(mailPort),
		mail.WithTLSPolicy(mailTLSPolicy))
	if err != nil {
		return err
	}
	return client.DialAndSend(message)
}

const emailTemplate = `
<!doctype html>
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office">

<head>
  <title></title>
  <!--[if !mso]><!-- -->
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <!--<![endif]-->
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">

  <style type="text/css">
    #outlook a {
      padding: 0;
    }
    .ReadMsgBody {
      width: 100%;
    }
    .ExternalClass {
      width: 100%;
    }
    .ExternalClass * {
      line-height: 100%;
    }
    body {
      margin: 0;
      padding: 0;
      -webkit-text-size-adjust: 100%;
      -ms-text-size-adjust: 100%;
    }
    table,
    td {
      border-collapse: collapse;
      mso-table-lspace: 0pt;
      mso-table-rspace: 0pt;
    }
    img {
      border: 0;
      height: auto;
      line-height: 100%;
      outline: none;
      text-decoration: none;
      -ms-interpolation-mode: bicubic;
    }
    p {
      display: block;
      margin: 13px 0;
    }
  </style>

  <!--[if !mso]><!-->
  <style type="text/css">
    @media only screen and (max-width:480px) {
      @-ms-viewport {
        width: 320px;
      }
      @viewport {
        width: 320px;
      }
    }
  </style>
  <!--<![endif]-->

  <!--[if mso]>
        <xml>
        <o:OfficeDocumentSettings>
          <o:AllowPNG/>
          <o:PixelsPerInch>96</o:PixelsPerInch>
        </o:OfficeDocumentSettings>
        </xml>
        <![endif]-->
  <!--[if lte mso 11]>
        <style type="text/css">
          .outlook-group-fix { width:100% !important; }
        </style>
        <![endif]-->
  <!--[if !mso]><!-->
  <link href="https://fonts.googleapis.com/css?family=Inter" rel="stylesheet" type="text/css">
  <style type="text/css">
    @import url(https://fonts.googleapis.com/css?family=Inter);
  </style>
  <!--<![endif]-->

  <style type="text/css">
    @media only screen and (min-width:480px) {
      .mj-column-per-100 {
        width: 100% !important;
        max-width: 100%;
      }
      .mj-column-per-49 {
        width: 49.5% !important;
        max-width: 49.5%;
      }
      .mj-column-per-1 {
        width: 1% !important;
        max-width: 1%;
      }
      .mj-column-per-50 {
        width: 50% !important;
        max-width: 50%;
      }
    }
  </style>
  <style type="text/css">
    @media only screen and (max-width:480px) {
      table.full-width-mobile {
        width: 100% !important;
      }
      td.full-width-mobile {
        width: auto !important;
      }
    }
  </style>
  <style type="text/css">
    .primary-link {
      color: #0a84ff;
      text-decoration: none;
      font-weight: bold;
    }
    .highlight {
      color: #0a84ff;
      font-weight: bold;
    }
  </style>
</head>

<body style="background-color:#f3f6f9;">
  <div style="background-color:#f3f6f9;">

    <!--[if mso | IE]>
      <table
         align="center" border="0" cellpadding="0" cellspacing="0" class="" style="width:600px;" width="600">
        <tr>
          <td style="line-height:0px;font-size:0px;mso-line-height-rule:exactly;">
      <![endif]-->
    <div style="Margin:0px auto;max-width:600px;">
      <table align="center" border="0" cellpadding="0" cellspacing="0" role="presentation" style="width:100%;">
        <tbody>
          <tr>
            <td style="direction:ltr;font-size:0px;padding:0;text-align:center;vertical-align:top;">
              <!--[if mso | IE]>
                  <table role="presentation" border="0" cellpadding="0" cellspacing="0">
        <tr>
            <td class="" style="vertical-align:top;width:600px;">
          <![endif]-->
              <div class="mj-column-per-100 outlook-group-fix" style="font-size:13px;text-align:left;direction:ltr;display:inline-block;vertical-align:top;width:100%;">
                <table border="0" cellpadding="0" cellspacing="0" role="presentation" style="vertical-align:top;" width="100%">
                  <tr>
                    <td align="left" style="font-size:0px;padding:16px;word-break:break-word;">
                      <table border="0" cellpadding="0" cellspacing="0" role="presentation" style="border-collapse:collapse;border-spacing:0px;">
                        <tbody>
                          <tr>
                            <td style="width:370px;">
                              <img alt="Twake Workplace" height="48" src="https://files.cozycloud.cc/cozy-mjml/twakeworkplacelogo.png" style="border:0;display:block;outline:none;text-decoration:none;height:48px;width:100%;" width="370" />
                            </td>
                          </tr>
                        </tbody>
                      </table>
                    </td>
                  </tr>
                </table>
              </div>
              <!--[if mso | IE]>
            </td>
        </tr>
                  </table>
                <![endif]-->
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <!--[if mso | IE]>
          </td>
        </tr>
      </table>
      <table
         align="center" border="0" cellpadding="0" cellspacing="0" class="" style="width:600px;" width="600">
        <tr>
          <td style="line-height:0px;font-size:0px;mso-line-height-rule:exactly;">
      <![endif]-->
    <div style="background:#ffffff;background-color:#ffffff;Margin:0px auto;border-radius:8px;max-width:600px;">
      <table align="center" border="0" cellpadding="0" cellspacing="0" role="presentation" style="background:#ffffff;background-color:#ffffff;width:100%;border-radius:8px;">
        <tbody>
          <tr>
            <td style="direction:ltr;font-size:0px;padding:0;text-align:center;vertical-align:top;">
              <!--[if mso | IE]>
                  <table role="presentation" border="0" cellpadding="0" cellspacing="0">
            <tr>
              <td class="" width="600px">
      <table
         align="center" border="0" cellpadding="0" cellspacing="0" class="" style="width:600px;" width="600">
        <tr>
          <td style="line-height:0px;font-size:0px;mso-line-height-rule:exactly;">
      <![endif]-->
              <div style="Margin:0px auto;max-width:600px;">
                <table align="center" border="0" cellpadding="0" cellspacing="0" role="presentation" style="width:100%;">
                  <tbody>
                    <tr>
                      <td style="direction:ltr;font-size:0px;padding:24px0 8px;text-align:center;vertical-align:top;">
                        <!--[if mso | IE]>
                  <table role="presentation" border="0" cellpadding="0" cellspacing="0">
        <tr>
            <td class="" style="vertical-align:top;width:600px;">
          <![endif]-->
                        <div class="mj-column-per-100 outlook-group-fix" style="font-size:13px;text-align:left;direction:ltr;display:inline-block;vertical-align:top;width:100%;">
                          <table border="0" cellpadding="0" cellspacing="0" role="presentation" style="vertical-align:top;" width="100%">
                            <tr>
                              <td align="left" style="font-size:0px;padding:0 24px 16px;word-break:break-word;">
                                <div style="font-family:inter,Arial;font-size:14px;font-weight:bold;line-height:1.5;text-align:left;color:#95999d;">
                                  <img src="https://files.cozycloud.cc/email-assets/stack/twake-download.png" width="16" height="16" style="vertical-align:sub;" /> {{.Title}}</div>
                              </td>
                            </tr>
                            <tr>
                              <td align="left" style="font-size:0px;padding:0 24px 16px;word-break:break-word;">
                                <div style="font-family:inter,Arial;font-size:16px;line-height:1.5;text-align:left;color:#32363f;"> Bonjour, </div>
                              </td>
                            </tr>
                            <tr>
                              <td align="left" style="font-size:0px;padding:0 24px 16px;word-break:break-word;">
                                <div style="font-family:inter,Arial;font-size:16px;line-height:1.5;text-align:left;color:#32363f;">{{.Text}}</div>
                              </td>
                            </tr>
                            <tr>
                              <td align="left" vertical-align="middle" style="font-size:0px;padding:0 24px 32px;word-break:break-word;">
                                <table border="0" cellpadding="0" cellspacing="0" role="presentation" style="border-collapse:separate;line-height:100%;">
                                  <tr>
                                    <td align="center" bgcolor="#297ef2" role="presentation" style="border:none;border-radius:32px;cursor:auto;padding:10px 16px;background:#297ef2;" valign="middle">
                                      <a href="{{.Link}}" style="background:#297ef2;color:#ffffff;font-family:inter,Arial;font-size:14px;font-weight:bold;line-height:1.43;Margin:0;text-decoration:none;text-transform:none;" target="_blank">
									  Voir le répertoire
									  </a>
                                    </td>
                                  </tr>
                                </table>
                              </td>
                            </tr>
                          </table>
                        </div>
                        <!--[if mso | IE]>
            </td>
        </tr>
                  </table>
                <![endif]-->
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
              <!--[if mso | IE]>
          </td>
        </tr>
      </table>
              </td>
            </tr>
                  </table>
                <![endif]-->
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <!--[if mso | IE]>
          </td>
        </tr>
      </table>
      <table
         align="center" border="0" cellpadding="0" cellspacing="0" class="" style="width:600px;" width="600">
        <tr>
          <td style="line-height:0px;font-size:0px;mso-line-height-rule:exactly;">
      <![endif]-->
    <div style="Margin:0px auto;max-width:600px;">
      <table align="center" border="0" cellpadding="0" cellspacing="0" role="presentation" style="width:100%;">
        <tbody>
          <tr>
            <td style="direction:ltr;font-size:0px;padding:0;text-align:center;vertical-align:top;">
              <!--[if mso | IE]>
                  <table role="presentation" border="0" cellpadding="0" cellspacing="0">
            <tr>
              <td class="" width="600px">
      <table
         align="center" border="0" cellpadding="0" cellspacing="0" class="" style="width:600px;" width="600">
        <tr>
          <td style="line-height:0px;font-size:0px;mso-line-height-rule:exactly;">
      <![endif]-->
              <div style="Margin:0px auto;max-width:600px;">
                <table align="center" border="0" cellpadding="0" cellspacing="0" role="presentation" style="width:100%;">
                  <tbody>
                    <tr>
                      <td style="direction:ltr;font-size:0px;padding:0;text-align:center;vertical-align:top;">
                        <!--[if mso | IE]>
                  <table role="presentation" border="0" cellpadding="0" cellspacing="0">
        <tr>
            <td class="" style="vertical-align:top;width:600px;">
          <![endif]-->
                        <div class="mj-column-per-100 outlook-group-fix" style="font-size:13px;text-align:left;direction:ltr;display:inline-block;vertical-align:top;width:100%;">
                          <table border="0" cellpadding="0" cellspacing="0" role="presentation" style="vertical-align:top;" width="100%">
                            <tr>
                              <td align="center" style="font-size:0px;padding:0;word-break:break-word;">
                                <div style="font-family:inter,Arial;font-size:16px;font-weight:bold;line-height:1.5;text-align:center;color:#0a84ff;">
								Twake Workplace héberge votre domicile numérique
								</div>
                              </td>
                            </tr>
                            <tr>
                              <td align="center" style="font-size:0px;padding:10px 25px;word-break:break-word;">
                                <div style="font-family:inter,Arial;font-size:14px;line-height:1.5;text-align:center;color:#95999d;">
								Hébergé en France - Respectueux de votre vie privée - Sécurisé
								</div>
                              </td>
                            </tr>
                          </table>
                        </div>
                        <!--[if mso | IE]>
            </td>
        </tr>
                  </table>
                <![endif]-->
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
              <!--[if mso | IE]>
          </td>
        </tr>
      </table>
              </td>
            </tr>
            <tr>
              <td class="" width="600px">
      <table
         align="center" border="0" cellpadding="0" cellspacing="0" class="" style="width:600px;" width="600">
        <tr>
          <td style="line-height:0px;font-size:0px;mso-line-height-rule:exactly;">
      <![endif]-->
              <div style="Margin:0px auto;max-width:600px;">
                <table align="center" border="0" cellpadding="0" cellspacing="0" role="presentation" style="width:100%;">
                  <tbody>
                    <tr>
                      <td style="direction:ltr;font-size:0px;padding:0;text-align:center;vertical-align:top;">
                        <!--[if mso | IE]>
                  <table role="presentation" border="0" cellpadding="0" cellspacing="0">
        <tr>
            <td class="" style="width:600px;">
          <![endif]-->
                        <div class="mj-column-per-100 outlook-group-fix" style="font-size:0;line-height:0;text-align:left;display:inline-block;width:100%;direction:ltr;">
                          <!--[if mso | IE]>
        <table  role="presentation" border="0" cellpadding="0" cellspacing="0">
          <tr>
              <td style="vertical-align:top;width:297px;">
              <![endif]-->
                          <div class="mj-column-per-49 outlook-group-fix" style="font-size:13px;text-align:left;direction:ltr;display:inline-block;vertical-align:top;width:49.5%;">
                            <table border="0" cellpadding="0" cellspacing="0" role="presentation" width="100%">
                              <tbody>
                                <tr>
                                  <td style="vertical-align:top;padding:0;">
                                    <table border="0" cellpadding="0" cellspacing="0" role="presentation" style="" width="100%">
                                      <tr>
                                        <td align="right" vertical-align="middle" style="font-size:0px;padding:0;word-break:break-word;">
                                          <table border="0" cellpadding="0" cellspacing="0" role="presentation" style="border-collapse:separate;line-height:100%;">
                                            <tr>
                                              <td align="center" bgcolor="transparent" role="presentation" style="border:none;border-radius:3px;cursor:auto;padding:10px 8px;background:transparent;" valign="middle">
                                                <a href="https://blog.cozy.io/fr/" style="background:transparent;color:#0a84ff;font-family:inter,Arial;font-size:12px;font-weight:bold;line-height:1.5;Margin:0;text-decoration:none;text-transform:none;" target="_blank"> Blog de Twake Workplace </a>
                                              </td>
                                            </tr>
                                          </table>
                                        </td>
                                      </tr>
                                    </table>
                                  </td>
                                </tr>
                              </tbody>
                            </table>
                          </div>
                          <!--[if mso | IE]>
              </td>
              <td style="vertical-align:top;width:6px;">
              <![endif]-->
                          <div class="mj-column-per-1 outlook-group-fix" style="font-size:13px;text-align:left;direction:ltr;display:inline-block;vertical-align:top;width:1%;">
                            <table border="0" cellpadding="0" cellspacing="0" role="presentation" width="100%">
                              <tbody>
                                <tr>
                                  <td style="vertical-align:top;padding:0;">
                                    <table border="0" cellpadding="0" cellspacing="0" role="presentation" style="" width="100%">
                                      <tr>
                                        <td align="center" style="font-size:0px;padding:5px 0;word-break:break-word;">
                                          <div style="font-family:inter,Arial;font-size:16px;line-height:1.5;text-align:center;color:#95999d;"> | </div>
                                        </td>
                                      </tr>
                                    </table>
                                  </td>
                                </tr>
                              </tbody>
                            </table>
                          </div>
                          <!--[if mso | IE]>
              </td>
              <td style="vertical-align:top;width:297px;" >
              <![endif]-->
                          <div class="mj-column-per-49 outlook-group-fix"style="font-size:13px;text-align:left;direction:ltr;display:inline-block;vertical-align:top;width:49.5%;">
                            <table border="0" cellpadding="0" cellspacing="0" role="presentation" width="100%">
                              <tbody>
                                <tr>
                                  <td style="vertical-align:top;padding:0;">
                                    <table border="0" cellpadding="0" cellspacing="0" role="presentation" style="" width="100%">
                                      <tr>
                                        <td align="left" vertical-align="middle" style="font-size:0px;padding:0;word-break:break-word;">
                                          <table border="0" cellpadding="0" cellspacing="0" role="presentation" style="border-collapse:separate;line-height:100%;">
                                            <tr>
                                              <td align="center" bgcolor="transparent" role="presentation" style="border:none;border-radius:3px;cursor:auto;padding:10px 8px;background:transparent;" valign="middle">
                                                <a href="https://support.cozy.io/" style="background:transparent;color:#0a84ff;font-family:inter,Arial;font-size:12px;font-weight:bold;line-height:1.5;Margin:0;text-decoration:none;text-transform:none;" target="_blank"> Aide et support </a>
                                              </td>
                                            </tr>
                                          </table>
                                        </td>
                                      </tr>
                                    </table>
                                  </td>
                                </tr>
                              </tbody>
                            </table>
                          </div>
                          <!--[if mso | IE]>
              </td>
          </tr>
          </table>
        <![endif]-->
                        </div>
                        <!--[if mso | IE]>
            </td>
        </tr>
                  </table>
                <![endif]-->
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
              <!--[if mso | IE]>
          </td>
        </tr>
      </table>
              </td>
            </tr>
            <tr>
              <td class="" width="600px" >
      <table
         align="center" border="0" cellpadding="0" cellspacing="0" class="" style="width:600px;" width="600" >
        <tr>
          <td style="line-height:0px;font-size:0px;mso-line-height-rule:exactly;">
      <![endif]-->
              <div style="Margin:0px auto;max-width:600px;">
                <table align="center" border="0" cellpadding="0" cellspacing="0" role="presentation" style="width:100%;">
                  <tbody>
                    <tr>
                      <td style="direction:ltr;font-size:0px;padding:20px;padding-bottom:5px;text-align:center;vertical-align:top;">
                        <!--[if mso | IE]>
                  <table role="presentation" border="0" cellpadding="0" cellspacing="0">
        <tr>
            <td class="" style="width:600px;" >
          <![endif]-->
                        <div class="mj-column-per-100 outlook-group-fix" style="font-size:0;line-height:0;text-align:left;display:inline-block;width:100%;direction:ltr;">
                          <!--[if mso | IE]>
        <table  role="presentation" border="0" cellpadding="0" cellspacing="0">
          <tr>
              <td style="vertical-align:top;width:300px;" >
              <![endif]-->
                          <div class="mj-column-per-50 outlook-group-fix"style="font-size:13px;text-align:left;direction:ltr;display:inline-block;vertical-align:top;width:50%;">
                            <table border="0" cellpadding="0" cellspacing="0" role="presentation" style="vertical-align:top;" width="100%">
                              <tr>
                                <td align="right" style="font-size:0px;padding:4px;word-break:break-word;">
                                  <table border="0" cellpadding="0" cellspacing="0" role="presentation" style="border-collapse:collapse;border-spacing:0px;">
                                    <tbody>
                                      <tr>
                                        <td style="width:130px;">
                                          <a href="https://itunes.apple.com/fr/developer/cozy-cloud/id1131616091?mt=8" target="_blank">
                                            <img alt="Appstore" height="auto" src="https://files.cozycloud.cc/cozy-mjml/twake-appstore-fr.png" style="border:0;display:block;outline:none;text-decoration:none;height:auto;width:100%;" width="130" />
                                          </a>
                                        </td>
                                      </tr>
                                    </tbody>
                                  </table>
                                </td>
                              </tr>
                            </table>
                          </div>
                          <!--[if mso | IE]>
              </td>
              <td style="vertical-align:top;width:300px;" >
              <![endif]-->
                          <div class="mj-column-per-50 outlook-group-fix" style="font-size:13px;text-align:left;direction:ltr;display:inline-block;vertical-align:top;width:50%;">
                            <table border="0" cellpadding="0" cellspacing="0" role="presentation" style="vertical-align:top;" width="100%">
                              <tr>
                                <td align="left" style="font-size:0px;padding:4px;word-break:break-word;">
                                  <table border="0" cellpadding="0" cellspacing="0" role="presentation" style="border-collapse:collapse;border-spacing:0px;">
                                    <tbody>
                                      <tr>
                                        <td style="width:130px;">
                                          <a href="https://play.google.com/store/apps/developer?id=Cozy+Cloud&hl=fr" target="_blank">
                                            <img alt="Play Store" height="auto" src="https://files.cozycloud.cc/cozy-mjml/twake-playstore-fr.png" style="border:0;display:block;outline:none;text-decoration:none;height:auto;width:100%;" width="130" />
                                          </a>
                                        </td>
                                      </tr>
                                    </tbody>
                                  </table>
                                </td>
                              </tr>
                            </table>
                          </div>
                          <!--[if mso | IE]>
              </td>
              <td style="vertical-align:top;width:600px;" >
              <![endif]-->
                          <div class="mj-column-per-100 outlook-group-fix" style="font-size:13px;text-align:left;direction:ltr;display:inline-block;vertical-align:top;width:100%;">
                            <table border="0" cellpadding="0" cellspacing="0" role="presentation" style="vertical-align:top;" width="100%">
                              <tr>
                                <td align="center" style="font-size:0px;padding:4px;word-break:break-word;">
                                  <table border="0" cellpadding="0" cellspacing="0" role="presentation" style="border-collapse:collapse;border-spacing:0px;">
                                    <tbody>
                                      <tr>
                                        <td style="width:130px;">
                                          <a href="https://cozy.io/fr/download/#desktop" target="_blank">
                                            <img alt="Cozy Desktop" height="auto" src="https://files.cozycloud.cc/cozy-mjml/twake-desktop-fr.png" style="border:0;display:block;outline:none;text-decoration:none;height:auto;width:100%;" width="130" />
                                          </a>
                                        </td>
                                      </tr>
                                    </tbody>
                                  </table>
                                </td>
                              </tr>
                            </table>
                          </div>
                          <!--[if mso | IE]>
              </td>
          </tr>
          </table>
        <![endif]-->
                        </div>
                        <!--[if mso | IE]>
            </td>
        </tr>
                  </table>
                <![endif]-->
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
              <!--[if mso | IE]>
          </td>
        </tr>
      </table>
              </td>
            </tr>
            <tr>
              <td class="" width="600px" >
      <table
         align="center" border="0" cellpadding="0" cellspacing="0" class="" style="width:600px;" width="600" >
        <tr>
          <td style="line-height:0px;font-size:0px;mso-line-height-rule:exactly;">
      <![endif]-->
              <div style="Margin:0px auto;max-width:600px;">
                <table align="center" border="0" cellpadding="0" cellspacing="0" role="presentation" style="width:100%;">
                  <tbody>
                    <tr>
                      <td style="direction:ltr;font-size:0px;padding:0;text-align:center;vertical-align:top;">
                        <!--[if mso | IE]>
                  <table role="presentation" border="0" cellpadding="0" cellspacing="0">
        <tr>
            <td class="" style="vertical-align:top;width:600px;" >
          <![endif]-->
                        <div class="mj-column-per-100 outlook-group-fix" style="font-size:13px;text-align:left;direction:ltr;display:inline-block;vertical-align:top;width:100%;">
                          <table border="0" cellpadding="0" cellspacing="0" role="presentation" style="vertical-align:top;" width="100%">
                            <tr>
                              <td align="center" style="font-size:0px;padding:10px 25px;word-break:break-word;">
                                <div style="font-family:inter,Arial;font-size:12px;line-height:1.5;text-align:center;color:#32363f;">
                                  <a href="https://cozy.io/fr/legal/" style="color:#5d6165;">Mentions légales</a>
                                </div>
                              </td>
                            </tr>
                          </table>
                        </div>
                        <!--[if mso | IE]>
            </td>
        </tr>
                  </table>
                <![endif]-->
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
              <!--[if mso | IE]>
          </td>
        </tr>
      </table>
              </td>
            </tr>
                  </table>
                <![endif]-->
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <!--[if mso | IE]>
          </td>
        </tr>
      </table>
      <![endif]-->
  </div>
</body>
</html>
`
