package request

type Authentication struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	PuzzleId  string `json:"puzzle_id"`
	Ans       string `json:"ans"`
	Logindata struct {
		V        string `json:"_v"`
		Datetime string `json:"datetime"`
	} `json:"logindata"`
}
