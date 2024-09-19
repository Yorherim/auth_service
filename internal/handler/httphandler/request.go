package httphandler

type SetUserInfoReq struct {
	Name string `json:"name"`
}

type ChangePswReq struct {
	Password string `json:"password"`
}

type AdminBlockUserReq struct {
	UserID string `json:"user_id"`
	Block  bool   `json:"block"`
}

type AdminSetRoleToUserReq struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
}

func (r SetUserInfoReq) IsValid() bool {
	return r.Name != ""
}

func (r ChangePswReq) IsValid() bool {
	return r.Password != ""
}
