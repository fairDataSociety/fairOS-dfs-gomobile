package fairos

//go:generate gomobile bind -o fairos.aar -target=android github.com/fairdatasociety/fairos

import (
	"encoding/json"
	"github.com/fairdatasociety/fairOS-dfs/pkg/dfs"
	"github.com/fairdatasociety/fairOS-dfs/pkg/logging"
	"github.com/sirupsen/logrus"
	"os"

	_ "golang.org/x/mobile/bind"
)

var api *dfs.DfsAPI

func Connect(dataDir, beeEndpoint, postageBlockId string, logLevel int) error {
	logger := logging.New(os.Stdout, logrus.Level(logLevel))
	var err error
	api, err = dfs.NewDfsAPI(
		dataDir,
		beeEndpoint,
		"",
		postageBlockId,
		logger,
	)
	return err
}

func CreateUser(username, password string) (string, error) {
	address, mnemonic, _, err := api.CreateUser(username, password, "", "")
	if err != nil {
		return "", err
	}
	data := map[string]string{}
	data["address"] = address
	data["mnemonic"] = mnemonic
	resp, _ := json.Marshal(data)
	return string(resp), nil
}

func LoginUser(username, password string) (string, error) {
	ui, err := api.LoginUser(username, password, "")
	if err != nil {
		return "", err
	}
	data := map[string]string{}
	data["sessionId"] = ui.GetSessionId()
	resp, _ := json.Marshal(data)
	return string(resp), nil
}

func ImportUserWithAddress(username, password, address string) (string, error) {
	ui, err := api.ImportUserUsingAddress(username, password, address, "")
	if err != nil {
		return "", err
	}
	resp, _ := json.Marshal(ui)
	return string(resp), err
}

func ImportUserWithMnemonic(username, password, mnemonic string) (string, error) {
	ui, err := api.ImportUserUsingMnemonic(username, password, mnemonic, "")
	if err != nil {
		return "", err
	}
	resp, _ := json.Marshal(ui)
	return string(resp), err
}

func IsUserPresent(username string) (string, error) {
	present := api.IsUserNameAvailable(username)
	data := map[string]bool{}
	data["present"] = present
	resp, _ := json.Marshal(data)
	return string(resp), nil
}

func IsUserLoggedIn(username string) (string, error) {
	present := api.IsUserLoggedIn(username)
	data := map[string]bool{}
	data["loggedin"] = present
	resp, _ := json.Marshal(data)
	return string(resp), nil
}

func LogoutUser(sessionId string) error {
	return api.LogoutUser(sessionId)
}

func ExportUser(sessionId string) (string, error) {
	name, address, err := api.ExportUser(sessionId)
	if err != nil {
		return "", err
	}
	data := map[string]string{}
	data["username"] = name
	data["address"] = address
	resp, _ := json.Marshal(data)
	return string(resp), nil
}

func DeleteUser(sessionId, password string) error {
	return api.DeleteUser(password, sessionId)
}

func StatUser(sessionId string) (string, error) {
	stat, err := api.GetUserStat(sessionId)
	if err != nil {
		return "", err
	}
	resp, _ := json.Marshal(stat)
	return string(resp), nil
}