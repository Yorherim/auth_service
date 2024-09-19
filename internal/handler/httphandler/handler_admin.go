package httphandler

import (
	"authservice/internal/domain"
	"authservice/internal/service"
	"errors"
	"fmt"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"net/http"
)

func AdminGetUserInfo(resp http.ResponseWriter, req *http.Request) {

	respBody := &HTTPResponse{}
	defer func() {
		resp.Write(respBody.Marshall())
	}()

	id := req.URL.Query().Get("user_id")
	userID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		resp.WriteHeader(http.StatusBadRequest)
		respBody.SetError(errors.New("invalid input"))
		return
	}

	info, err := service.GetUserFullInfo(userID)
	if err != nil {
		resp.WriteHeader(http.StatusNotFound)
		respBody.SetError(err)
	}

	respBody.SetData(info)
}

/*
AdminBlockUser

небольшое пояснение кода:
По-моему, не логично, если один админ может забанить другого админа.
Может получится так, что админы друг друга перебанят, и не останется админов.
Для этого добавил роль "root" - супер-админ. Пользователь с ролью "root" может забанить любого пользователя,
но его самого не может забанить никто.
*/
func AdminBlockUser(resp http.ResponseWriter, req *http.Request) {
	respBody := &HTTPResponse{}
	defer func() {
		resp.Write(respBody.Marshall())
	}()

	var body AdminBlockUserReq
	if err := readBody(req, &body); err != nil {
		resp.WriteHeader(http.StatusUnprocessableEntity)
		respBody.SetError(err)
		return
	}

	id := req.Header.Get(HeaderUserID)

	if id == body.UserID {
		resp.WriteHeader(http.StatusBadRequest)
		respBody.SetError(errors.New("can't ban yourself"))
		return
	}

	senderID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		resp.WriteHeader(http.StatusBadRequest)
		respBody.SetError(errors.New("invalid input"))
		return
	}

	senderInfo, err := service.GetUserFullInfo(senderID)
	if err != nil {
		resp.WriteHeader(http.StatusInternalServerError)
		respBody.SetError(err)
		return
	}

	userID, err := primitive.ObjectIDFromHex(body.UserID)
	if err != nil {
		resp.WriteHeader(http.StatusBadRequest)
		respBody.SetError(errors.New("invalid input"))
		return
	}

	userInfo, err := service.GetUserFullInfo(userID)
	if err != nil {
		resp.WriteHeader(http.StatusNotFound)
		respBody.SetError(err)
		return
	}

	userIsAdminOrRoot := userInfo.Role == domain.UserRoleAdmin || userInfo.Role == domain.UserRoleRoot

	if userIsAdminOrRoot && senderInfo.Role != domain.UserRoleRoot {
		resp.WriteHeader(http.StatusBadRequest)
		respBody.SetError(errors.New("can't ban admin"))
		return
	}

	if err := service.BlockUser(userID, body.Block); err != nil {
		resp.WriteHeader(http.StatusNotFound)
		respBody.SetError(err)
	}
}

/*
AdminSetRoleToUser

небольшое пояснение кода:
Также, как и в AdminBlockUser, админ не может сменить роль другого админа.
Может получится так, что админы друг другу снимут роли, и не останется админов вовсе.
Только root может сменить роль админа.

Наверное, было бы логично, если бы только root мог давать роль админа пользователям,
но я оставил эту возможность админам.
*/
func AdminSetRoleToUser(resp http.ResponseWriter, req *http.Request) {
	respBody := &HTTPResponse{}
	defer func() {
		resp.Write(respBody.Marshall())
	}()

	var body AdminSetRoleToUserReq
	if err := readBody(req, &body); err != nil {
		resp.WriteHeader(http.StatusUnprocessableEntity)
		respBody.SetError(err)
		return
	}

	if body.Role != domain.UserRoleAdmin && body.Role != domain.UserRoleDefault {
		resp.WriteHeader(http.StatusBadRequest)
		respBody.SetError(errors.New("invalid user role"))
		return
	}

	id := req.Header.Get(HeaderUserID)

	if id == body.UserID {
		resp.WriteHeader(http.StatusBadRequest)
		respBody.SetError(errors.New("can't change role of yourself"))
		return
	}

	senderID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		resp.WriteHeader(http.StatusBadRequest)
		respBody.SetError(errors.New("invalid input"))
		return
	}

	senderInfo, err := service.GetUserFullInfo(senderID)
	if err != nil {
		resp.WriteHeader(http.StatusInternalServerError)
		respBody.SetError(err)
		return
	}

	userID, err := primitive.ObjectIDFromHex(body.UserID)
	if err != nil {
		resp.WriteHeader(http.StatusBadRequest)
		respBody.SetError(errors.New("invalid input"))
		return
	}

	userInfo, err := service.GetUserFullInfo(userID)
	if err != nil {
		resp.WriteHeader(http.StatusNotFound)
		respBody.SetError(err)
		return
	}

	userIsAdminOrRoot := userInfo.Role == domain.UserRoleAdmin || userInfo.Role == domain.UserRoleRoot

	if userIsAdminOrRoot && senderInfo.Role != domain.UserRoleRoot {
		resp.WriteHeader(http.StatusBadRequest)
		respBody.SetError(errors.New("can't change role of admin"))
		return
	}

	if err := service.SetRoleToUser(userID, body.Role); err != nil {
		resp.WriteHeader(http.StatusNotFound)
		respBody.SetError(err)
	}
}

/*
AdminChangePsw

небольшое пояснение кода:
Здесь не стал делать проверку на root для того, чтобы админы могли восстановить пароль в случае,
если root его забудет.
*/
func AdminChangePsw(resp http.ResponseWriter, req *http.Request) {
	respBody := &HTTPResponse{}
	defer func() {
		resp.Write(respBody.Marshall())
	}()

	var body domain.UserPassword
	if err := readBody(req, &body); err != nil {
		resp.WriteHeader(http.StatusUnprocessableEntity)
		respBody.SetError(err)
		return
	}

	if !body.IsValid() {
		resp.WriteHeader(http.StatusBadRequest)
		respBody.SetError(errors.New("invalid input"))
		return
	}

	if err := service.ChangePsw(&body); err != nil {
		resp.WriteHeader(http.StatusNotFound)
		respBody.SetError(err)
		return
	}

	userInfo, err := service.GetUserFullInfo(body.ID)
	if err != nil {
		resp.WriteHeader(http.StatusInternalServerError)
		respBody.SetError(err)
		return
	}

	newPassword := body.Password
	userName := userInfo.Name
	userEmail := userInfo.Email

	msgTheme := "New Password"
	msg := fmt.Sprintf(
		"Dear %s, your password has been reset. Your new password is: %s. Please login and change it after accessing your account.",
		userName, newPassword)

	// не совсем уверен, куда нужно положить работу с email, поэтому положил в сервисы, но мне кажется, что это неверное решение
	// буду благодарен, если подскажите здесь, куда эту функцию лучше положить
	if err := service.SendEmail(userEmail, msgTheme, msg); err != nil {
		resp.WriteHeader(http.StatusInternalServerError)
		respBody.SetError(err)
	}
}
