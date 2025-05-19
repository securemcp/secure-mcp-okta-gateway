package auth

const (
	InvalidClientMetadata = "invalid_client_metadata"
	InvalidRequest        = "invalid_request"
	UnauthorizedClient    = "unauthorized_client"
	ServerError           = "server_error"
)

type AuthError struct {
	AuthJsonError
	AuthRedirectError
}

type AuthJsonError struct {
	Code        string `json:"error"`
	Description string `json:"error_description"`
}

type AuthRedirectError struct {
	RedirectURI      string
	ErrorCode        string
	ErrorDescription string
	State            string
}
