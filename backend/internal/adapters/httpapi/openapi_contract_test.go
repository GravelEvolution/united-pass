package httpapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestOpenAPIMiniProgramAndQRContracts(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "openapi", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(raw, &document); err != nil {
		t.Fatalf("parse OpenAPI: %v", err)
	}
	paths := openAPIMap(t, document, "paths")
	for _, path := range []string{
		"/api/v1/auth/miniprogram/sessions",
		"/api/v1/auth/miniprogram/sessions/mfa",
		"/api/v1/auth/wechat/sessions",
	} {
		operation := openAPIMap(t, openAPIMap(t, paths, path), "post")
		if !openAPIHasParameterRef(operation, "#/components/parameters/X-MiniProgram-Client") {
			t.Fatalf("%s missing native marker", path)
		}
		response := openAPIMap(t, openAPIMap(t, operation, "responses"), "200")
		schema := openAPIMap(t, openAPIMap(t, openAPIMap(t, response, "content"), "application/json"), "schema")
		if got, _ := schema["$ref"].(string); got != "#/components/schemas/MiniProgramSessionResponse" {
			t.Fatalf("%s success schema=%q", path, got)
		}
		if headers, _ := response["headers"].(map[string]any); headers["Set-Cookie"] != nil {
			t.Fatalf("%s native response declares Set-Cookie", path)
		}
	}

	protected := map[string]string{
		"/api/v1/me/miniprogram/profile":                                            "post",
		"/api/v1/me/wechat/phone":                                                   "post",
		"/api/v1/auth/qr/challenges/{challengeId}/approve":                          "post",
		"/api/v1/dreamup/mobile/assertions":                                         "post",
		"/api/v1/dreamup/mobile/resume-upload-assertions":                           "post",
		"/api/v1/admin/dreamup/eligibility":                                         "get",
		"/api/v1/admin/dreamup/events/{eventId}/operations/status":                  "get",
		"/api/v1/admin/dreamup/events/{eventId}/content":                            "get",
		"/api/v1/admin/dreamup/events/{eventId}/content/intro":                      "put",
		"/api/v1/admin/dreamup/events/{eventId}/announcements":                      "post",
		"/api/v1/admin/dreamup/events/{eventId}/announcements/{contentId}":          "patch",
		"/api/v1/admin/dreamup/events/{eventId}/teams":                              "get",
		"/api/v1/admin/dreamup/events/{eventId}/contact-submissions":                "get",
		"/api/v1/admin/dreamup/events/{eventId}/contact-submissions/{submissionId}": "get",
	}
	for path, method := range protected {
		item := openAPIMap(t, paths, path)
		operation := openAPIMap(t, item, method)
		security, _ := operation["security"].([]any)
		if !openAPIHasSecurityScheme(security, "MiniProgramBearer") {
			t.Fatalf("%s %s missing native bearer", method, path)
		}
		if !openAPIHasParameterRef(operation, "#/components/parameters/X-MiniProgram-Client") && !openAPIHasParameterRef(operation, "#/components/parameters/X-MiniProgram-Client-When-Bearer") && !openAPIHasParameterRef(item, "#/components/parameters/X-MiniProgram-Client-When-Bearer") {
			t.Fatalf("%s %s missing native marker", method, path)
		}
	}

	consume := openAPIMap(t, openAPIMap(t, paths, "/api/v1/auth/qr/challenges/{challengeId}/consume"), "post")
	responses := openAPIMap(t, consume, "responses")
	for statusCode, expectedStatus := range map[string]string{"200": "authenticated", "202": "pending"} {
		response := openAPIMap(t, responses, statusCode)
		schema := openAPIMap(t, openAPIMap(t, openAPIMap(t, response, "content"), "application/json"), "schema")
		status := openAPIMap(t, openAPIMap(t, schema, "properties"), "status")
		if got, _ := status["const"].(string); got != expectedStatus {
			t.Fatalf("QR %s status=%q", statusCode, got)
		}
	}

	for _, path := range []string{"/api/v1/dreamup/mobile/assertions", "/api/v1/dreamup/mobile/resume-upload-assertions"} {
		operation := openAPIMap(t, openAPIMap(t, paths, path), "post")
		responses := openAPIMap(t, operation, "responses")
		for _, status := range []string{"400", "401", "404", "413", "415", "422", "429", "500"} {
			if _, ok := responses[status]; !ok {
				t.Fatalf("%s missing actual error response %s", path, status)
			}
		}
	}
	ordinary := openAPIMap(t, openAPIMap(t, paths, "/api/v1/dreamup/mobile/assertions"), "post")
	ordinarySchema := openAPIMap(t, openAPIMap(t, openAPIMap(t, openAPIMap(t, ordinary, "requestBody"), "content"), "application/json"), "schema")
	bodyField := openAPIMap(t, openAPIMap(t, ordinarySchema, "properties"), "body")
	bodyDescription, _ := bodyField["description"].(string)
	for _, limit := range []string{"UTF-8", "8 KiB", "seat confirmation", "admission entry-code", "16 KiB", "64 KiB"} {
		if !strings.Contains(bodyDescription, limit) {
			t.Fatalf("ordinary assertion body omits %q byte contract", limit)
		}
	}
	resume := openAPIMap(t, openAPIMap(t, paths, "/api/v1/dreamup/mobile/resume-upload-assertions"), "post")
	resumeSchema := openAPIMap(t, openAPIMap(t, openAPIMap(t, openAPIMap(t, resume, "requestBody"), "content"), "application/json"), "schema")
	resumeProperties := openAPIMap(t, resumeSchema, "properties")
	fileName := openAPIMap(t, resumeProperties, "fileName")
	if fileName["x-max-utf8-bytes"] != 255 || !strings.Contains(fileName["description"].(string), "255 UTF-8 bytes") {
		t.Fatalf("resume filename UTF-8 byte contract=%v", fileName)
	}
	byteSize := openAPIMap(t, resumeProperties, "byteSize")
	if byteSize["maximum"] != 5242880 {
		t.Fatalf("resume byteSize maximum=%v", byteSize["maximum"])
	}
	contentType := openAPIMap(t, resumeProperties, "contentType")
	mediaTypes, _ := contentType["enum"].([]any)
	if len(mediaTypes) != 3 {
		t.Fatalf("resume MIME allowlist=%v", mediaTypes)
	}
	bodySHA256 := openAPIMap(t, resumeProperties, "bodySha256")
	if bodySHA256["pattern"] != "^[0-9a-f]{64}$" {
		t.Fatalf("resume digest pattern=%v", bodySHA256["pattern"])
	}

	contactList := openAPIMap(t, openAPIMap(t, paths, "/api/v1/admin/dreamup/events/{eventId}/contact-submissions"), "get")
	contactDescription, _ := contactList["description"].(string)
	if !strings.Contains(contactDescription, "event.contact_submission.manage") || strings.Contains(contactDescription, "`event.audit.read`") {
		t.Fatalf("contact capability contract=%q", contactDescription)
	}
	parameters, _ := contactList["parameters"].([]any)
	var cursor map[string]any
	for _, raw := range parameters {
		parameter, _ := raw.(map[string]any)
		if parameter["name"] == "cursor" {
			cursor = parameter
			break
		}
	}
	if cursor == nil {
		t.Fatal("contact-submission list omits cursor query")
	}
	cursorSchema := openAPIMap(t, cursor, "schema")
	if cursorSchema["maxLength"] != 512 || cursorSchema["pattern"] != "^[A-Za-z0-9_-]+$" {
		t.Fatalf("contact cursor schema=%v", cursorSchema)
	}
	contactSuccess := openAPIMap(t, openAPIMap(t, contactList, "responses"), "200")
	contactSchema := openAPIMap(t, openAPIMap(t, openAPIMap(t, contactSuccess, "content"), "application/json"), "schema")
	contactProperties := openAPIMap(t, contactSchema, "properties")
	if contactProperties["submissions"] == nil || contactProperties["nextCursor"] == nil {
		t.Fatalf("contact pagination response=%v", contactProperties)
	}
	if contactSuccess["x-data-classification"] != "participant_contact" {
		t.Fatalf("contact response classification=%v", contactSuccess["x-data-classification"])
	}
	cacheControl := openAPIMap(t, openAPIMap(t, contactSuccess, "headers"), "Cache-Control")
	if openAPIMap(t, cacheControl, "schema")["const"] != "no-store" {
		t.Fatalf("contact Cache-Control contract=%v", cacheControl)
	}
	submissions := openAPIMap(t, contactProperties, "submissions")
	if submissions["maxItems"] != 100 {
		t.Fatalf("contact submissions bound=%v", submissions["maxItems"])
	}
	submission := openAPIMap(t, submissions, "items")
	if submission["additionalProperties"] != false {
		t.Fatalf("contact submission is not closed: %v", submission)
	}
	submissionProperties := openAPIMap(t, submission, "properties")
	payloadVariants, _ := openAPIMap(t, submissionProperties, "payload")["oneOf"].([]any)
	resolutionVariants, _ := openAPIMap(t, submissionProperties, "resolution")["oneOf"].([]any)
	if len(payloadVariants) != 3 || len(resolutionVariants) != 2 {
		t.Fatalf("contact variants payload=%v resolution=%v", payloadVariants, resolutionVariants)
	}
	if submissionProperties["category"] == nil {
		t.Fatal("contact submission omits structured category")
	}
	foundEmergency := false
	for _, raw := range payloadVariants {
		variant, _ := raw.(map[string]any)
		if variant["additionalProperties"] != false {
			t.Fatalf("contact payload variant is not closed: %v", variant)
		}
		properties, _ := variant["properties"].(map[string]any)
		if category, _ := properties["category"].(map[string]any); category["const"] == "emergency" {
			foundEmergency = properties["eventType"] != nil && properties["location"] != nil && properties["contact"] != nil && properties["details"] != nil
		}
	}
	if !foundEmergency {
		t.Fatal("contact payload omits structured emergency variant")
	}
	nextCursor := openAPIMap(t, contactProperties, "nextCursor")
	cursorTypes, _ := nextCursor["type"].([]any)
	if len(cursorTypes) != 2 || cursorTypes[0] != "string" || cursorTypes[1] != "null" || nextCursor["nullable"] != nil {
		t.Fatalf("contact nextCursor 3.1 nullability=%v", nextCursor)
	}

	contactResolution := openAPIMap(t, openAPIMap(t, paths, "/api/v1/admin/dreamup/events/{eventId}/contact-submissions/{submissionId}/resolution"), "post")
	resolutionSuccess := openAPIMap(t, openAPIMap(t, contactResolution, "responses"), "200")
	if resolutionSuccess["x-data-classification"] != "participant_contact_resolution" {
		t.Fatalf("contact resolution classification=%v", resolutionSuccess["x-data-classification"])
	}
	resolutionHeaders := openAPIMap(t, resolutionSuccess, "headers")
	resolutionCache := openAPIMap(t, openAPIMap(t, resolutionHeaders, "Cache-Control"), "schema")
	if resolutionCache["const"] != "no-store" || resolutionHeaders["ETag"] == nil {
		t.Fatalf("contact resolution headers=%v", resolutionHeaders)
	}
	resolutionSchema := openAPIMap(t, openAPIMap(t, openAPIMap(t, resolutionSuccess, "content"), "application/json"), "schema")
	if resolutionSchema["additionalProperties"] != false {
		t.Fatalf("contact resolution response is not closed: %v", resolutionSchema)
	}
	resolutionObject := openAPIMap(t, openAPIMap(t, resolutionSchema, "properties"), "resolution")
	if resolutionObject["additionalProperties"] != false || openAPIMap(t, resolutionObject, "properties")["updatedAt"] == nil {
		t.Fatalf("contact resolution object=%v", resolutionObject)
	}

	components := openAPIMap(t, document, "components")
	nativeScheme := openAPIMap(t, openAPIMap(t, components, "securitySchemes"), "MiniProgramBearer")
	if nativeScheme["type"] != "http" || nativeScheme["scheme"] != "bearer" {
		t.Fatalf("native bearer scheme=%v", nativeScheme)
	}
	nativeResponse := openAPIMap(t, openAPIMap(t, components, "schemas"), "MiniProgramSessionResponse")
	properties := openAPIMap(t, nativeResponse, "properties")
	if properties["sessionBearer"] == nil || properties["csrfToken"] != nil {
		t.Fatalf("native response properties=%v", properties)
	}
}

func TestOpenAPIWeChatOnboardingContract(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "openapi", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(raw, &document); err != nil {
		t.Fatalf("parse OpenAPI: %v", err)
	}
	paths := openAPIMap(t, document, "paths")
	for _, path := range []string{
		"/api/v1/auth/wechat/onboarding",
		"/api/v1/auth/wechat/onboarding/complete",
		"/api/v1/auth/wechat/onboarding/mfa",
	} {
		operation := openAPIMap(t, openAPIMap(t, paths, path), "post")
		if !openAPIHasParameterRef(operation, "#/components/parameters/X-MiniProgram-Client") {
			t.Fatalf("%s missing native marker", path)
		}
		responses := openAPIMap(t, operation, "responses")
		if _, ok := responses["404"]; !ok {
			t.Fatalf("%s missing feature-disabled 404", path)
		}
	}

	complete := openAPIMap(t, openAPIMap(t, paths, "/api/v1/auth/wechat/onboarding/complete"), "post")
	responses := openAPIMap(t, complete, "responses")
	mfaResponse := openAPIMap(t, openAPIMap(t, openAPIMap(t, responses, "202"), "content"), "application/json")
	mfaSchema := openAPIMap(t, mfaResponse, "schema")
	if got, _ := mfaSchema["$ref"].(string); got != "#/components/schemas/WeChatOnboardingMFARequiredResponse" {
		t.Fatalf("onboarding MFA response schema=%q", got)
	}
	unauthorized := openAPIMap(t, responses, "401")
	if got, _ := unauthorized["$ref"].(string); got != "#/components/responses/WeChatOnboardingCompleteUnauthorized" {
		t.Fatalf("onboarding complete 401 response=%q", got)
	}

	schemas := openAPIMap(t, openAPIMap(t, document, "components"), "schemas")
	mfaRequired := openAPIMap(t, schemas, "WeChatOnboardingMFARequiredResponse")
	mfaToken := openAPIMap(t, openAPIMap(t, mfaRequired, "properties"), "mfaToken")
	if got, _ := mfaToken["pattern"].(string); got != "^[A-Za-z0-9_-]{43}$" {
		t.Fatalf("onboarding MFA token pattern=%q", got)
	}
	description, _ := mfaRequired["description"].(string)
	if !strings.Contains(description, "/api/v1/auth/wechat/onboarding/mfa") || strings.Contains(description, "POST /api/v1/auth/sessions/mfa") {
		t.Fatalf("onboarding MFA continuation description=%q", description)
	}

	contract := string(raw)
	for _, stable := range []string{
		"wechat.onboarding_expired",
		"wechat.onboarding_email_password_mismatch",
		"wechat.onboarding_conflict",
		"此邮箱已存在账号，请设定原始密码以进行绑定",
	} {
		if !strings.Contains(contract, stable) {
			t.Fatalf("onboarding contract missing %q", stable)
		}
	}
}

func TestOpenAPIDreamUPEligibilityContentAndContactDetailContracts(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "openapi", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(raw, &document); err != nil {
		t.Fatalf("parse OpenAPI: %v", err)
	}
	paths := openAPIMap(t, document, "paths")
	components := openAPIMap(t, document, "components")
	schemas := openAPIMap(t, components, "schemas")

	eligibility := openAPIMap(t, openAPIMap(t, paths, "/api/v1/admin/dreamup/eligibility"), "get")
	eligibilityDescription, _ := eligibility["description"].(string)
	if !strings.Contains(eligibilityDescription, "event.dashboard.read") || !strings.Contains(eligibilityDescription, "Generic account personas are not authority") || strings.Contains(eligibilityDescription, "step-up required") {
		t.Fatalf("eligibility disclosure/authority contract=%q", eligibilityDescription)
	}
	eligibilitySuccess := openAPIMap(t, openAPIMap(t, eligibility, "responses"), "200")
	eligibilityRef, _ := openAPIMap(t, openAPIMap(t, openAPIMap(t, eligibilitySuccess, "content"), "application/json"), "schema")["$ref"].(string)
	if eligibilityRef != "#/components/schemas/DreamUPAdminEligibilityResponse" {
		t.Fatalf("eligibility schema=%q", eligibilityRef)
	}
	eligibilitySchema := openAPIMap(t, schemas, "DreamUPAdminEligibilityResponse")
	eligibilityProperties := openAPIMap(t, eligibilitySchema, "properties")
	if eligibilitySchema["additionalProperties"] != false || len(eligibilityProperties) != 1 || eligibilityProperties["eligible"] == nil {
		t.Fatalf("eligibility leaked fields: %v", eligibilitySchema)
	}

	operationStatus := openAPIMap(t, openAPIMap(t, paths, "/api/v1/admin/dreamup/events/{eventId}/operations/status"), "get")
	if !openAPIHasParameterRef(operationStatus, "#/components/parameters/Idempotency-Key") || openAPIHasParameterRef(operationStatus, "#/components/parameters/X-Reauthentication-Token") {
		t.Fatalf("operation status parameters=%v", operationStatus["parameters"])
	}
	statusDescription, _ := operationStatus["description"].(string)
	for _, phrase := range []string{"initiating account", "never reissues", "never returns", "refetch"} {
		if !strings.Contains(statusDescription, phrase) {
			t.Fatalf("operation status description missing %q: %q", phrase, statusDescription)
		}
	}
	statusSuccess := openAPIMap(t, openAPIMap(t, operationStatus, "responses"), "200")
	statusRef, _ := openAPIMap(t, openAPIMap(t, openAPIMap(t, statusSuccess, "content"), "application/json"), "schema")["$ref"].(string)
	if statusRef != "#/components/schemas/DreamUPMutationStatusResponse" {
		t.Fatalf("operation status schema=%q", statusRef)
	}
	statusSchema := openAPIMap(t, schemas, "DreamUPMutationStatusResponse")
	operationSchema := openAPIMap(t, openAPIMap(t, statusSchema, "properties"), "operation")
	properties := openAPIMap(t, operationSchema, "properties")
	if statusSchema["additionalProperties"] != false || operationSchema["additionalProperties"] != false || len(properties) != 5 || properties["receiptHash"] != nil || properties["responseBody"] != nil || properties["idempotencyKey"] != nil {
		t.Fatalf("operation status leaked or omitted fields: %v", statusSchema)
	}

	contentRead := openAPIMap(t, openAPIMap(t, paths, "/api/v1/admin/dreamup/events/{eventId}/content"), "get")
	if !strings.Contains(contentRead["description"].(string), "event.content.manage") || !strings.Contains(contentRead["description"].(string), "fresh") {
		t.Fatalf("content read assurance=%q", contentRead["description"])
	}
	if !openAPIHasParameterRef(contentRead, "#/components/parameters/DreamUP-X-Reauthentication-Token") {
		t.Fatal("content draft read is missing its transport-conditional proof header")
	}
	contentReadSuccess := openAPIMap(t, openAPIMap(t, contentRead, "responses"), "200")
	if got, _ := openAPIMap(t, openAPIMap(t, openAPIMap(t, contentReadSuccess, "content"), "application/json"), "schema")["$ref"].(string); got != "#/components/schemas/DreamUPContentResponse" {
		t.Fatalf("content read schema=%q", got)
	}

	mutations := []struct {
		path, method, requestSchema string
	}{
		{"/api/v1/admin/dreamup/events/{eventId}/content/intro", "put", "#/components/schemas/DreamUPIntroMutationRequest"},
		{"/api/v1/admin/dreamup/events/{eventId}/announcements", "post", "#/components/schemas/DreamUPAnnouncementMutationRequest"},
		{"/api/v1/admin/dreamup/events/{eventId}/announcements/{contentId}", "patch", "#/components/schemas/DreamUPAnnouncementMutationRequest"},
	}
	for _, contract := range mutations {
		operation := openAPIMap(t, openAPIMap(t, paths, contract.path), contract.method)
		for _, parameter := range []string{"#/components/parameters/DreamUP-X-Reauthentication-Token", "#/components/parameters/Idempotency-Key", "#/components/parameters/DreamUP-If-Match"} {
			if !openAPIHasParameterRef(operation, parameter) {
				t.Errorf("%s %s missing %s", contract.method, contract.path, parameter)
			}
		}
		requestSchema := openAPIMap(t, openAPIMap(t, openAPIMap(t, openAPIMap(t, operation, "requestBody"), "content"), "application/json"), "schema")
		if got, _ := requestSchema["$ref"].(string); got != contract.requestSchema {
			t.Errorf("%s %s request schema=%q", contract.method, contract.path, got)
		}
		successSchema := openAPIMap(t, openAPIMap(t, openAPIMap(t, openAPIMap(t, openAPIMap(t, operation, "responses"), "200"), "content"), "application/json"), "schema")
		if got, _ := successSchema["$ref"].(string); got != "#/components/schemas/DreamUPContentResponse" {
			t.Errorf("%s %s response schema=%q", contract.method, contract.path, got)
		}
	}
	introAction := openAPIMap(t, openAPIMap(t, openAPIMap(t, schemas, "DreamUPIntroMutationRequest"), "properties"), "action")
	introValues, _ := introAction["enum"].([]any)
	if len(introValues) != 2 || introValues[0] != "save_draft" || introValues[1] != "publish" {
		t.Fatalf("intro actions=%v", introValues)
	}
	announcementAction := openAPIMap(t, openAPIMap(t, openAPIMap(t, schemas, "DreamUPAnnouncementMutationRequest"), "properties"), "action")
	announcementValues, _ := announcementAction["enum"].([]any)
	if len(announcementValues) != 3 || announcementValues[2] != "archive" {
		t.Fatalf("announcement actions=%v", announcementValues)
	}
	contentDocument := openAPIMap(t, schemas, "DreamUPContentDocument")
	contentDocumentProperties := openAPIMap(t, contentDocument, "properties")
	if contentDocument["additionalProperties"] != false || contentDocumentProperties["revision"] == nil || contentDocumentProperties["publishedAt"] == nil {
		t.Fatalf("content document contract=%v", contentDocument)
	}
	contentBlock := openAPIMap(t, schemas, "DreamUPContentBlock")
	blockVariants, _ := contentBlock["oneOf"].([]any)
	if len(blockVariants) != 4 {
		t.Fatalf("content block variants=%v", blockVariants)
	}
	for _, rawVariant := range blockVariants {
		variant, _ := rawVariant.(map[string]any)
		if variant["additionalProperties"] != false {
			t.Fatalf("content block variant is open: %v", variant)
		}
	}
	dreamupIfMatch := openAPIMap(t, openAPIMap(t, components, "parameters"), "DreamUP-If-Match")
	if openAPIMap(t, dreamupIfMatch, "schema")["pattern"] != `^"(0|[1-9][0-9]*)"$` {
		t.Fatalf("DreamUP If-Match=%v", dreamupIfMatch)
	}
	ordinaryIfMatch := openAPIMap(t, openAPIMap(t, components, "parameters"), "If-Match")
	if openAPIMap(t, ordinaryIfMatch, "schema")["pattern"] != `^"[1-9][0-9]*"$` {
		t.Fatalf("global If-Match was broadened: %v", ordinaryIfMatch)
	}
	reauthHeader := openAPIMap(t, openAPIMap(t, components, "parameters"), "X-Reauthentication-Token")
	reauthSchema := openAPIMap(t, reauthHeader, "schema")
	if reauthHeader["required"] != true || reauthSchema["minLength"] != 43 || reauthSchema["maxLength"] != 43 || reauthSchema["pattern"] != `^[A-Za-z0-9_-]{43}$` {
		t.Fatalf("DreamUP grant header is not exact opaque-token shape: %v", reauthHeader)
	}

	contactDetail := openAPIMap(t, openAPIMap(t, paths, "/api/v1/admin/dreamup/events/{eventId}/contact-submissions/{submissionId}"), "get")
	contactSuccess := openAPIMap(t, openAPIMap(t, contactDetail, "responses"), "200")
	if contactSuccess["x-data-classification"] != "participant_contact" || openAPIMap(t, openAPIMap(t, contactSuccess, "headers"), "Cache-Control")["schema"] == nil {
		t.Fatalf("contact detail classification/headers=%v", contactSuccess)
	}
	contactDetailSchema := openAPIMap(t, openAPIMap(t, openAPIMap(t, contactSuccess, "content"), "application/json"), "schema")
	contactSubmissionRef, _ := openAPIMap(t, contactDetailSchema, "properties")["submission"].(map[string]any)
	if contactSubmissionRef["$ref"] != "#/components/schemas/DreamUPContactSubmission" {
		t.Fatalf("contact detail submission schema=%v", contactSubmissionRef)
	}
	contactSubmission := openAPIMap(t, schemas, "DreamUPContactSubmission")
	contactProperties := openAPIMap(t, contactSubmission, "properties")
	if contactSubmission["additionalProperties"] != false || contactProperties["category"] == nil {
		t.Fatalf("contact detail category/closure=%v", contactSubmission)
	}
}

func TestOpenAPIWeChatRegistrationAndEmailChangeSecurityContracts(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "openapi", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(raw, &document); err != nil {
		t.Fatalf("parse OpenAPI: %v", err)
	}
	paths := openAPIMap(t, document, "paths")
	wechat := openAPIMap(t, openAPIMap(t, paths, "/api/v1/registrations/wechat"), "post")
	description, _ := wechat["description"].(string)
	for _, requirement := range []string{"UP_WECHAT_MINIPROGRAM_ENABLED", "UP_WECHAT_MINIPROGRAM_REGISTRATION_ENABLED", "UP_PUBLIC_REGISTRATION_ENABLED", "X-UnitedPass-Client: dreamup-miniprogram", "retryable"} {
		if !strings.Contains(description, requirement) {
			t.Fatalf("WeChat registration description missing %q", requirement)
		}
	}
	if !openAPIHasParameterRef(wechat, "#/components/parameters/X-MiniProgram-Client") {
		t.Fatal("WeChat registration missing native marker")
	}
	emailChange := openAPIMap(t, openAPIMap(t, paths, "/api/v1/me/email-change"), "post")
	if !openAPIHasParameterRef(emailChange, "#/components/parameters/X-Reauthentication-Token") {
		t.Fatal("email change missing strong reauthentication grant")
	}
	request := openAPIMap(t, openAPIMap(t, openAPIMap(t, document, "components"), "schemas"), "ReauthenticationRequest")
	action := openAPIMap(t, openAPIMap(t, request, "properties"), "action")
	values, _ := action["enum"].([]any)
	found := false
	for _, value := range values {
		found = found || value == "account.email.change"
	}
	if !found {
		t.Fatal("reauthentication actions omit account.email.change")
	}
}

func TestOpenAPIAdminStepUpContract(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "openapi", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(raw, &document); err != nil {
		t.Fatalf("parse OpenAPI: %v", err)
	}
	paths := openAPIMap(t, document, "paths")

	type operationContract struct {
		method, success, schema string
		parameters              []string
		errors                  []string
	}
	contracts := map[string]operationContract{
		"/api/v1/admin/step-up/challenge": {
			method: "get", success: "200", schema: "#/components/schemas/AdminStepUpChallengeResponse",
			parameters: []string{"#/components/parameters/DreamUPEventIdQuery"},
			errors:     []string{"400", "401", "403", "404", "422", "500"},
		},
		"/api/v1/admin/step-up/enroll": {
			method: "post", success: "201", schema: "#/components/schemas/AdminStepUpMutationResponse",
			parameters: []string{"#/components/parameters/X-CSRF-Token", "#/components/parameters/Idempotency-Key"},
			errors:     []string{"400", "401", "403", "404", "409", "422", "500"},
		},
		"/api/v1/admin/step-up/verify": {
			method: "post", success: "200", schema: "#/components/schemas/AdminStepUpMutationResponse",
			parameters: []string{"#/components/parameters/X-CSRF-Token", "#/components/parameters/Idempotency-Key"},
			errors:     []string{"400", "401", "403", "404", "409", "422", "423", "429", "500"},
		},
		"/api/v1/admin/step-up/rotate": {
			method: "post", success: "200", schema: "#/components/schemas/AdminStepUpMutationResponse",
			parameters: []string{"#/components/parameters/X-CSRF-Token", "#/components/parameters/Idempotency-Key", "#/components/parameters/If-Match"},
			errors:     []string{"400", "401", "403", "404", "409", "422", "423", "428", "429", "500"},
		},
	}

	for path, contract := range contracts {
		t.Run(path, func(t *testing.T) {
			pathItem := openAPIMap(t, paths, path)
			operation := openAPIMap(t, pathItem, contract.method)
			security, ok := operation["security"].([]any)
			securityObject := map[string]any{}
			if ok && len(security) == 1 {
				securityObject, _ = security[0].(map[string]any)
			}
			if _, ok := securityObject["SessionCookie"]; !ok {
				t.Fatalf("%s %s must require SessionCookie", contract.method, path)
			}
			for _, parameter := range contract.parameters {
				if !openAPIHasParameterRef(operation, parameter) {
					t.Errorf("missing parameter %s", parameter)
				}
			}
			responses := openAPIMap(t, operation, "responses")
			response := openAPIMap(t, responses, contract.success)
			content := openAPIMap(t, response, "content")
			media := openAPIMap(t, content, "application/json")
			schema := openAPIMap(t, media, "schema")
			if got, _ := schema["$ref"].(string); got != contract.schema {
				t.Errorf("success schema=%q want=%q", got, contract.schema)
			}
			for _, status := range contract.errors {
				errorResponse := openAPIMap(t, responses, status)
				if ref, _ := errorResponse["$ref"].(string); ref == "" {
					content := openAPIMap(t, errorResponse, "content")
					media := openAPIMap(t, content, "application/json")
					schema := openAPIMap(t, media, "schema")
					if got, _ := schema["$ref"].(string); got != "#/components/schemas/ErrorResponse" {
						t.Errorf("error %s schema=%q", status, got)
					}
				}
			}
		})
	}
}

func TestOpenAPIDreamUPAdmissionBFFContract(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "openapi", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	paths := openAPIMap(t, document, "paths")
	highRisk := map[string]map[string]bool{
		"/api/v1/admin/dreamup/events/{eventId}/content":                                                   {"get": true},
		"/api/v1/admin/dreamup/events/{eventId}/content/intro":                                             {"put": true},
		"/api/v1/admin/dreamup/events/{eventId}/announcements":                                             {"post": true},
		"/api/v1/admin/dreamup/events/{eventId}/announcements/{contentId}":                                 {"patch": true},
		"/api/v1/admin/dreamup/events/{eventId}/contact-submissions":                                       {"get": true},
		"/api/v1/admin/dreamup/events/{eventId}/contact-submissions/{submissionId}":                        {"get": true},
		"/api/v1/admin/dreamup/events/{eventId}/contact-submissions/{submissionId}/resolution":             {"post": true},
		"/api/v1/admin/dreamup/events/{eventId}/applications/{applicationId}/reviews/me":                   {"put": true},
		"/api/v1/admin/dreamup/events/{eventId}/applications/{applicationId}/admission-consensus":          {"get": true},
		"/api/v1/admin/dreamup/events/{eventId}/applications/{applicationId}/admission-consensus/approval": {"put": true, "delete": true},
		"/api/v1/admin/dreamup/events/{eventId}/applications/{applicationId}/decision":                     {"post": true},
		"/api/v1/admin/dreamup/events/{eventId}/checkins/scan":                                             {"post": true},
	}
	for path, methods := range map[string][]string{
		"/.well-known/dreamup-admin-jwks.json":                                                             {"get", "head"},
		"/.well-known/dreamup-mobile-jwks.json":                                                            {"get", "head"},
		"/api/v1/admin/dreamup/eligibility":                                                                {"get"},
		"/api/v1/admin/dreamup/events":                                                                     {"get"},
		"/api/v1/admin/dreamup/session":                                                                    {"get"},
		"/api/v1/admin/dreamup/events/{eventId}/operations/status":                                         {"get"},
		"/api/v1/admin/dreamup/events/{eventId}/content":                                                   {"get"},
		"/api/v1/admin/dreamup/events/{eventId}/content/intro":                                             {"put"},
		"/api/v1/admin/dreamup/events/{eventId}/announcements":                                             {"post"},
		"/api/v1/admin/dreamup/events/{eventId}/announcements/{contentId}":                                 {"patch"},
		"/api/v1/admin/dreamup/events/{eventId}/teams":                                                     {"get"},
		"/api/v1/admin/dreamup/events/{eventId}/contact-submissions":                                       {"get"},
		"/api/v1/admin/dreamup/events/{eventId}/contact-submissions/{submissionId}":                        {"get"},
		"/api/v1/admin/dreamup/events/{eventId}/contact-submissions/{submissionId}/resolution":             {"post"},
		"/api/v1/admin/dreamup/events/{eventId}/applications":                                              {"get"},
		"/api/v1/admin/dreamup/events/{eventId}/applications/{applicationId}":                              {"get"},
		"/api/v1/admin/dreamup/events/{eventId}/applications/{applicationId}/reviews/me":                   {"put"},
		"/api/v1/admin/dreamup/events/{eventId}/applications/{applicationId}/admission-consensus":          {"get"},
		"/api/v1/admin/dreamup/events/{eventId}/applications/{applicationId}/admission-consensus/approval": {"put", "delete"},
		"/api/v1/admin/dreamup/events/{eventId}/applications/{applicationId}/decision":                     {"post"},
		"/api/v1/admin/dreamup/events/{eventId}/checkins/scan":                                             {"post"},
	} {
		item := openAPIMap(t, paths, path)
		for _, method := range methods {
			operation := openAPIMap(t, item, method)
			if strings.HasPrefix(path, "/.well-known/") {
				continue
			}
			security, _ := operation["security"].([]any)
			if len(security) == 0 {
				t.Fatalf("%s %s missing session security", method, path)
			}
			if !openAPIHasSecurityScheme(security, "SessionCookie") || !openAPIHasSecurityScheme(security, "MiniProgramBearer") {
				t.Fatalf("%s %s missing SessionCookie", method, path)
			}
			hasReauth := openAPIHasParameterRef(operation, "#/components/parameters/DreamUP-X-Reauthentication-Token")
			if hasReauth != highRisk[path][method] {
				t.Fatalf("%s %s reauthentication header=%v want=%v", method, path, hasReauth, highRisk[path][method])
			}
			if openAPIHasParameterRef(operation, "#/components/parameters/X-Reauthentication-Token") {
				t.Fatalf("%s %s incorrectly declares the unconditional one-shot header", method, path)
			}
		}
	}
	versionedMutations := []struct {
		path   string
		method string
	}{
		{"/api/v1/admin/dreamup/events/{eventId}/contact-submissions/{submissionId}/resolution", "post"},
		{"/api/v1/admin/dreamup/events/{eventId}/applications/{applicationId}/reviews/me", "put"},
		{"/api/v1/admin/dreamup/events/{eventId}/applications/{applicationId}/admission-consensus/approval", "put"},
		{"/api/v1/admin/dreamup/events/{eventId}/applications/{applicationId}/admission-consensus/approval", "delete"},
		{"/api/v1/admin/dreamup/events/{eventId}/applications/{applicationId}/decision", "post"},
		{"/api/v1/admin/dreamup/events/{eventId}/checkins/scan", "post"},
	}
	for _, mutation := range versionedMutations {
		operation := openAPIMap(t, openAPIMap(t, paths, mutation.path), mutation.method)
		if !openAPIHasParameterRef(operation, "#/components/parameters/DreamUP-If-Match") {
			t.Errorf("%s %s omits the DreamUP zero-or-positive If-Match contract", mutation.method, mutation.path)
		}
	}
	dreamupIfMatch := openAPIMap(t, openAPIMap(t, openAPIMap(t, document, "components"), "parameters"), "DreamUP-If-Match")
	if got := openAPIMap(t, dreamupIfMatch, "schema")["pattern"]; got != `^"(0|[1-9][0-9]*)"$` {
		t.Fatalf("DreamUP If-Match pattern=%v, want zero-or-positive strong version", got)
	}
	withdraw := openAPIMap(t, openAPIMap(t, paths, "/api/v1/admin/dreamup/events/{eventId}/applications/{applicationId}/admission-consensus/approval"), "delete")
	if _, present := withdraw["requestBody"]; present {
		t.Fatal("bodyless admission approval withdrawal unexpectedly requires a request body")
	}
	componentParameters := openAPIMap(t, openAPIMap(t, document, "components"), "parameters")
	dreamUPReauth := openAPIMap(t, componentParameters, "DreamUP-X-Reauthentication-Token")
	if dreamUPReauth["name"] != "X-Reauthentication-Token" || dreamUPReauth["in"] != "header" || dreamUPReauth["required"] != false {
		t.Fatalf("DreamUP conditional reauthentication header=%v", dreamUPReauth)
	}
	dreamUPReauthDescription, _ := dreamUPReauth["description"].(string)
	for _, requirement := range []string{"native Mini", "Program bearer", "existing first-party cookie website", "account security epoch", "five minutes", "never falls back"} {
		if !strings.Contains(dreamUPReauthDescription, requirement) {
			t.Fatalf("DreamUP conditional reauthentication description omits %q: %q", requirement, dreamUPReauthDescription)
		}
	}
	globalReauth := openAPIMap(t, componentParameters, "X-Reauthentication-Token")
	if globalReauth["required"] != true {
		t.Fatalf("global one-shot reauthentication header was weakened: %v", globalReauth)
	}
	for _, path := range []string{"/api/v1/admin/step-up/enroll", "/api/v1/admin/dreamup/step-up/enroll"} {
		enrollment := openAPIMap(t, openAPIMap(t, paths, path), "post")
		description, _ := enrollment["description"].(string)
		for _, requirement := range []string{"fresh provider-backed", "super_admin", "top_admin", "no existing challenge", "session.reauthentication_required"} {
			if !strings.Contains(description, requirement) {
				t.Fatalf("%s enrollment description omits %q: %q", path, requirement, description)
			}
		}
	}
	schemas := openAPIMap(t, openAPIMap(t, document, "components"), "schemas")
	verifyRequest := openAPIMap(t, schemas, "AdminStepUpVerifyRequest")
	required, _ := verifyRequest["required"].([]any)
	if !openAPIStringListContains(required, "target") {
		t.Fatalf("admin step-up verify required=%v, target must be mandatory", required)
	}
	action := openAPIMap(t, openAPIMap(t, verifyRequest, "properties"), "action")
	actions, _ := action["enum"].([]any)
	for _, highRiskAction := range []string{
		"event.application.review",
		"event.application.approve_admission",
		"event.application.decide",
		"event.registration.manage",
		"event.checkin.scan",
		"event.checkin.manage_window",
		"event.identity_access.consume",
		"event.identity.read_restricted",
		"event.legal.read",
		"event.application.export",
		"event.audit.read",
		"event.contact_submission.manage",
		"event.content.manage",
		"system.role_migration.read",
	} {
		if !openAPIStringListContains(actions, highRiskAction) {
			t.Fatalf("admin step-up actions=%v omit high-risk action %q", actions, highRiskAction)
		}
	}
	target := openAPIMap(t, openAPIMap(t, verifyRequest, "properties"), "target")
	targetDescription, _ := target["description"].(string)
	for _, requirement := range []string{"canonical JSON tuple", "alternate JSON spellings", "cross-event", "action/resource-kind mismatches"} {
		if !strings.Contains(targetDescription, requirement) {
			t.Fatalf("admin step-up target description omits %q: %q", requirement, targetDescription)
		}
	}
	verifyOperation := openAPIMap(t, openAPIMap(t, paths, "/api/v1/admin/dreamup/step-up/verify"), "post")
	verifyDescription, _ := verifyOperation["description"].(string)
	for _, requirement := range []string{"30 minutes", "Every mutation", "application review", "check-in scan", "native Mini Program", "existing cookie website", "cannot fall back"} {
		if !strings.Contains(verifyDescription, requirement) {
			t.Fatalf("admin step-up verify description omits %q: %q", requirement, verifyDescription)
		}
	}
}

func openAPIStringListContains(values []any, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestOpenAPIIdentityAccessContract(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "openapi", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(raw, &document); err != nil {
		t.Fatalf("parse OpenAPI: %v", err)
	}
	paths := openAPIMap(t, document, "paths")

	type operationContract struct {
		method, success, schema string
		parameters              []string
	}
	contracts := map[string]operationContract{
		"/api/v1/admin/events/{eventId}/identity-access/requests": {
			method: "post", success: "201", schema: "#/components/schemas/IdentityAccessRequest",
			parameters: []string{"#/components/parameters/DreamUPEventIdPath", "#/components/parameters/X-CSRF-Token", "#/components/parameters/Idempotency-Key"},
		},
		"/api/v1/admin/events/{eventId}/identity-access/approval-queue": {
			method: "get", success: "200", schema: "#/components/schemas/IdentityAccessRequestPage",
			parameters: []string{"#/components/parameters/DreamUPEventIdPath", "#/components/parameters/CursorQuery", "#/components/parameters/LimitQuery", "#/components/parameters/SortQuery", "#/components/parameters/IdentityAccessStatusQuery"},
		},
		"/api/v1/admin/events/{eventId}/identity-access/requests/{requestId}/approve": {
			method: "post", success: "200", schema: "#/components/schemas/IdentityAccessDecisionResponse",
			parameters: []string{"#/components/parameters/DreamUPEventIdPath", "#/components/parameters/IdentityAccessRequestIdPath", "#/components/parameters/X-CSRF-Token", "#/components/parameters/Idempotency-Key", "#/components/parameters/If-Match", "#/components/parameters/X-Reauthentication-Token"},
		},
		"/api/v1/admin/events/{eventId}/identity-access/grants/{grantId}/claim": {
			method: "post", success: "202", schema: "#/components/schemas/IdentityAccessClaimResponse",
			parameters: []string{"#/components/parameters/DreamUPEventIdPath", "#/components/parameters/IdentityAccessGrantIdPath", "#/components/parameters/X-CSRF-Token", "#/components/parameters/Idempotency-Key", "#/components/parameters/If-Match"},
		},
	}

	for path, contract := range contracts {
		t.Run(path, func(t *testing.T) {
			operation := openAPIMap(t, openAPIMap(t, paths, path), contract.method)
			security, _ := operation["security"].([]any)
			if len(security) != 1 {
				t.Fatalf("%s %s must have one security requirement", contract.method, path)
			}
			securityObject, _ := security[0].(map[string]any)
			if _, ok := securityObject["SessionCookie"]; !ok {
				t.Fatalf("%s %s must require SessionCookie", contract.method, path)
			}
			for _, parameter := range contract.parameters {
				if !openAPIHasParameterRef(operation, parameter) {
					t.Errorf("missing parameter %s", parameter)
				}
			}
			responses := openAPIMap(t, operation, "responses")
			response := openAPIMap(t, responses, contract.success)
			content := openAPIMap(t, response, "content")
			media := openAPIMap(t, content, "application/json")
			schema := openAPIMap(t, media, "schema")
			if got, _ := schema["$ref"].(string); got != contract.schema {
				t.Errorf("success schema=%q want=%q", got, contract.schema)
			}
		})
	}

	components := openAPIMap(t, document, "components")
	schemas := openAPIMap(t, components, "schemas")
	for _, name := range []string{"IdentityAccessRequest", "IdentityAccessDecisionResponse", "IdentityAccessClaimResponse"} {
		schema := openAPIMap(t, schemas, name)
		properties := openAPIMap(t, schema, "properties")
		for _, forbidden := range []string{"reason", "reasonId", "claimNonce", "fieldSetHash", "roleBindingId", "challengeVersion"} {
			if _, ok := properties[forbidden]; ok {
				t.Errorf("%s must not expose %s", name, forbidden)
			}
		}
	}
}

func TestOpenAPIRegistrationContract(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "openapi", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(raw, &document); err != nil {
		t.Fatalf("parse OpenAPI: %v", err)
	}
	paths := openAPIMap(t, document, "paths")
	contracts := map[string]struct{ success, schema string }{
		"/api/v1/registrations":              {success: "201", schema: "#/components/schemas/RegistrationCreateResponse"},
		"/api/v1/registrations/email/verify": {success: "200", schema: "#/components/schemas/RegistrationVerifyResponse"},
		"/api/v1/registrations/email/resend": {success: "202", schema: "#/components/schemas/RegistrationResendResponse"},
	}
	for path, contract := range contracts {
		operation := openAPIMap(t, openAPIMap(t, paths, path), "post")
		if !openAPIHasParameterRef(operation, "#/components/parameters/RegistrationOrigin") {
			t.Errorf("%s missing strict Origin parameter", path)
		}
		response := openAPIMap(t, openAPIMap(t, operation, "responses"), contract.success)
		schema := openAPIMap(t, openAPIMap(t, openAPIMap(t, response, "content"), "application/json"), "schema")
		if got, _ := schema["$ref"].(string); got != contract.schema {
			t.Errorf("%s success schema=%q want=%q", path, got, contract.schema)
		}
	}

	schemas := openAPIMap(t, openAPIMap(t, document, "components"), "schemas")
	resendProperties := openAPIMap(t, openAPIMap(t, schemas, "RegistrationResendRequest"), "properties")
	if _, ok := resendProperties["userId"]; ok {
		t.Fatal("registration resend must not accept caller-selected userId")
	}
	verifyProperties := openAPIMap(t, openAPIMap(t, schemas, "RegistrationVerifyRequest"), "properties")
	code := openAPIMap(t, verifyProperties, "code")
	if writeOnly, _ := code["writeOnly"].(bool); !writeOnly {
		t.Fatal("registration verification code must be writeOnly")
	}
}

func TestOpenAPIAccountEmailChangeCodeContract(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "openapi", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(raw, &document); err != nil {
		t.Fatalf("parse OpenAPI: %v", err)
	}

	paths := openAPIMap(t, document, "paths")
	operation := openAPIMap(t, openAPIMap(t, paths, "/api/v1/me/email-change/verify"), "post")
	requestBody := openAPIMap(t, operation, "requestBody")
	content := openAPIMap(t, requestBody, "content")
	media := openAPIMap(t, content, "application/json")
	schema := openAPIMap(t, media, "schema")
	properties := openAPIMap(t, schema, "properties")
	code := openAPIMap(t, properties, "code")

	if got, _ := code["pattern"].(string); got != "^[A-Z0-9]{6}$" {
		t.Fatalf("email-change code pattern = %q, want uppercase alphanumeric provider format", got)
	}
	if got, _ := code["minLength"].(int); got != 6 {
		t.Fatalf("email-change code minLength = %d, want 6", got)
	}
	if got, _ := code["maxLength"].(int); got != 6 {
		t.Fatalf("email-change code maxLength = %d, want 6", got)
	}
}

func TestOpenAPIRegistrationBlockRevokeContract(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "openapi", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(raw, &document); err != nil {
		t.Fatalf("parse OpenAPI: %v", err)
	}
	paths := openAPIMap(t, document, "paths")
	operation := openAPIMap(t, openAPIMap(t, paths, "/api/v1/admin/registration-defense/blocks/revoke"), "post")
	security, _ := operation["security"].([]any)
	if len(security) != 1 {
		t.Fatal("registration block revoke must require one session security scheme")
	}
	securityObject, _ := security[0].(map[string]any)
	if _, ok := securityObject["SessionCookie"]; !ok {
		t.Fatal("registration block revoke must require SessionCookie")
	}
	if !openAPIHasParameterRef(operation, "#/components/parameters/X-CSRF-Token") {
		t.Fatal("registration block revoke must require X-CSRF-Token")
	}
	if !openAPIHasParameterRef(operation, "#/components/parameters/X-Reauthentication-Token") {
		t.Fatal("registration block revoke must require a target-bound reauthentication grant")
	}
	requestBody := openAPIMap(t, operation, "requestBody")
	content := openAPIMap(t, requestBody, "content")
	media := openAPIMap(t, content, "application/json")
	schema := openAPIMap(t, media, "schema")
	if got, _ := schema["$ref"].(string); got != "#/components/schemas/RegistrationAbuseBlockRevokeRequest" {
		t.Fatalf("request schema=%q", got)
	}
	responses := openAPIMap(t, operation, "responses")
	for _, status := range []string{"204", "400", "401", "403", "413", "422", "429", "500"} {
		if _, ok := responses[status]; !ok {
			t.Errorf("missing response %s", status)
		}
	}
	components := openAPIMap(t, document, "components")
	schemas := openAPIMap(t, components, "schemas")
	revokeSchema := openAPIMap(t, schemas, "RegistrationAbuseBlockRevokeRequest")
	properties := openAPIMap(t, revokeSchema, "properties")
	required, _ := revokeSchema["required"].([]any)
	hasEncoding := false
	for _, field := range required {
		hasEncoding = hasEncoding || field == "valueEncoding"
	}
	if !hasEncoding {
		t.Fatal("valueEncoding must be required to avoid raw/digest ambiguity")
	}
	encoding := openAPIMap(t, properties, "valueEncoding")
	values, _ := encoding["enum"].([]any)
	if len(values) != 2 || values[0] != "raw" || values[1] != "sha256" {
		t.Fatalf("valueEncoding enum=%#v", values)
	}
	if constraints, _ := revokeSchema["allOf"].([]any); len(constraints) == 0 {
		t.Fatal("IP raw-only conditional constraint is missing")
	}
	for _, forbidden := range []string{"redisKey", "key", "prefix", "digest"} {
		if _, ok := properties[forbidden]; ok {
			t.Errorf("operator contract must not expose %s", forbidden)
		}
	}
	reauthRequest := openAPIMap(t, schemas, "ReauthenticationRequest")
	reauthProperties := openAPIMap(t, reauthRequest, "properties")
	action := openAPIMap(t, reauthProperties, "action")
	actions, _ := action["enum"].([]any)
	foundUnblockAction := false
	for _, value := range actions {
		foundUnblockAction = foundUnblockAction || value == "registration.abuse.unblock"
	}
	if !foundUnblockAction {
		t.Fatal("reauthentication contract must expose registration.abuse.unblock")
	}
}

func openAPIMap(t *testing.T, value any, key string) map[string]any {
	t.Helper()
	object, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("OpenAPI value for %q is %T, want object", key, value)
	}
	nested, ok := object[key].(map[string]any)
	if !ok {
		t.Fatalf("OpenAPI object missing %q", key)
	}
	return nested
}

func openAPIHasParameterRef(operation map[string]any, want string) bool {
	parameters, _ := operation["parameters"].([]any)
	for _, value := range parameters {
		parameter, _ := value.(map[string]any)
		if got, _ := parameter["$ref"].(string); got == want {
			return true
		}
	}
	return false
}

func openAPIHasSecurityScheme(requirements []any, want string) bool {
	for _, value := range requirements {
		requirement, _ := value.(map[string]any)
		if _, ok := requirement[want]; ok {
			return true
		}
	}
	return false
}
