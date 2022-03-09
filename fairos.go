package fairos

//go:generate gomobile bind -o fairos.aar -target=android github.com/fairdatasociety/fairos

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/dustin/go-humanize"
	"github.com/fairdatasociety/fairOS-dfs/pkg/collection"
	"github.com/fairdatasociety/fairOS-dfs/pkg/dfs"
	"github.com/fairdatasociety/fairOS-dfs/pkg/logging"
	"github.com/fairdatasociety/fairOS-dfs/pkg/utils"
	"github.com/sirupsen/logrus"
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

func NewPod(sessionId, podName, password string) (string, error) {
	_, err := api.CreatePod(podName, password, sessionId)
	if err != nil {
		return "", err
	}
	return "pod created successfully", nil
}

func PodOpen(sessionId, podName, password string) (string, error) {
	_, err := api.OpenPod(podName, password, sessionId)
	if err != nil {
		return "", err
	}
	return "pod created successfully", nil
}

func PodClose(sessionId, podName string) error {
	return api.ClosePod(podName, sessionId)
}

func PodDelete(sessionId, podName, password string) error {
	return api.DeletePod(podName, password, sessionId)
}

func PodSync(sessionId, podName string) error {
	return api.SyncPod(podName, sessionId)
}

func PodList(sessionId string) (string, error) {
	ownPods, sharedPods, err :=  api.ListPods(sessionId)
	if err != nil {
		return "", err
	}
	data := map[string]interface{}{}
	data["pods"] = ownPods
	data["sharedPods"] = sharedPods
	resp, _ := json.Marshal(data)
	return string(resp), nil
}

func PodStat(sessionId, podName string) (string, error) {
	stat, err := api.PodStat(podName, sessionId)
	if err != nil {
		return "", err
	}
	resp, _ := json.Marshal(stat)
	return string(resp), nil
}

func PodShare(sessionId, podName, password string) (string, error) {
	reference, err := api.PodShare(podName, password, sessionId)
	if err != nil {
		return "", err
	}
	data := map[string]string{}
	data["pod_sharing_reference"] = reference
	resp, _ := json.Marshal(data)
	return string(resp), nil
}

func PodReceive(sessionId, podSharingReference string) (string, error) {
	ref, err := utils.ParseHexReference(podSharingReference)
	if err != nil {
		return "", err
	}
	pi, err := api.PodReceive(sessionId, ref)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("public pod \"%s\", added as shared pod", pi.GetPodName()), nil
}

func PodReceiveInfo(sessionId, podSharingReference string) (string, error) {
	ref, err := utils.ParseHexReference(podSharingReference)
	if err != nil {
		return "", err
	}
	shareInfo, err := api.PodReceiveInfo(sessionId, ref)
	if err != nil {
		return "", err
	}
	resp, _ := json.Marshal(shareInfo)
	return string(resp), nil
}

func DirPresent(sessionId, podName, dirPath string) (string, error) {
	present, err := api.IsDirPresent(podName, dirPath, sessionId)
	if err != nil {
		return "", err
	}
	data := map[string]bool{}
	data["present"] = present
	resp, _ := json.Marshal(data)
	return string(resp), nil
}

func DirMake(sessionId, podName, dirPath string) (string, error) {
	err := api.Mkdir(podName, dirPath, sessionId)
	if err != nil {
		return "", err
	}
	return string("directory created successfully"), nil
}

func DirRemove(sessionId, podName, dirPath string) (string, error) {
	err := api.RmDir(podName, dirPath, sessionId)
	if err != nil {
		return "", err
	}
	return string("directory removed successfully"), nil
}

func DirList(sessionId, podName, dirPath string) (string, error) {
	dirs, files, err := api.ListDir(podName, dirPath, sessionId)
	if err != nil {
		return "", err
	}
	data := map[string]interface{}{}
	data["files"] = files
	data["dirs"] = dirs
	resp, _ := json.Marshal(data)
	return string(resp), nil
}

func DirStat(sessionId, podName, dirPath string) (string, error) {
	stat, err := api.DirectoryStat(podName, dirPath, sessionId)
	if err != nil {
		return "", err
	}
	resp, _ := json.Marshal(stat)
	return string(resp), nil
}

func FileShare(sessionId, podName, dirPath, destinationUser string) (string, error) {
	ref, err := api.ShareFile(podName, dirPath, destinationUser, sessionId)
	if err != nil {
		return "", err
	}
	data := map[string]string{}
	data["file_sharing_reference"] = ref
	resp, _ := json.Marshal(data)
	return string(resp), err
}

func FileReceive(sessionId, podName, directory, fileSharingReference string) (string, error) {
	ref, err := utils.ParseSharingReference(fileSharingReference)
	if err != nil {
		return "", err
	}
	filePath, err := api.ReceiveFile(podName, sessionId, ref, directory)
	if err != nil {
		return "", err
	}
	data := map[string]string{}
	data["file_name"] = filePath
	resp, _ := json.Marshal(data)
	return string(resp), err
}

func FileReceiveInfo(sessionId, podName, fileSharingReference string) (string, error) {
	ref, err := utils.ParseSharingReference(fileSharingReference)
	if err != nil {
		return "", err
	}
	receiveInfo, err := api.ReceiveInfo(podName, sessionId, ref)
	if err != nil {
		return "", err
	}
	resp, _ := json.Marshal(receiveInfo)
	return string(resp), err
}

func FileDelete(sessionId, podName, filePath string) error {
	return api.DeleteFile(podName, filePath, sessionId)
}

func FileStat(sessionId, podName, filePath string) (string, error) {
	stat, err := api.FileStat(podName, filePath, sessionId)
	if err != nil {
		return "", err
	}
	resp, _ := json.Marshal(stat)
	return string(resp), err
}

func FileUpload(sessionId, podName, filePath, dirPath, compression, blockSize string) error {
	fileInfo, err := os.Lstat(filePath)
	if err != nil {
		return err
	}
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()
	bs, err := humanize.ParseBytes(blockSize)
	if err != nil {
		return err
	}
	return api.UploadFile(podName, fileInfo.Name(), sessionId, fileInfo.Size(), f, dirPath, compression, uint32(bs))
}

func FileDownload(sessionId, podName, filePath  string) ([]byte, error) {
	r, _, err := api.DownloadFile(podName, filePath, sessionId)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(r)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func KVNewStore(sessionId, podName, tableName, indexType string) (string, error) {
	if indexType == "" {
		indexType = "string"
	}

	var idxType collection.IndexType
	switch indexType {
	case "string":
		idxType = collection.StringIndex
	case "number":
		idxType = collection.NumberIndex
	case "bytes":
	default:
		return "", fmt.Errorf("invalid indexType. only string and number are allowed")
	}
	err := api.KVCreate(sessionId, podName, tableName, idxType)
	if err != nil {
		return "", err
	}
	return "kv store created", nil
}
func KVList(sessionId, podName string) (string, error) {
	collections, err := api.KVList(sessionId, podName)
	if err != nil {
		return "", err
	}
	resp, _ := json.Marshal(collections)
	return string(resp), err
}
func KVOpen(sessionId, podName, tableName string) error {
	return api.KVOpen(sessionId, podName, tableName)
}

func KVDelete(sessionId, podName, tableName string) error {
	return api.KVDelete(sessionId, podName, tableName)
}

func KVCount(sessionId, podName, tableName string) (string, error) {
	count, err := api.KVCount(sessionId, podName, tableName)
	if err != nil {
		return "", err
	}
	resp, _ := json.Marshal(count)
	return string(resp), err
}

func KVEntryPut(sessionId, podName, tableName, key string, value []byte) error {
	return api.KVPut(sessionId, podName, tableName, key, value)
}

func KVEntryGet(sessionId, podName, tableName, key string) ([]byte, error) {
	_, data, err := api.KVGet(sessionId, podName, tableName, key)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func KVEntryDelete(sessionId, podName, tableName, key string) error {
	_, err :=  api.KVDel(sessionId, podName, tableName, key)
	return err
}

func KVLoadCSV(sessionId, podName, tableName, filePath, memory string) (string, error) {
	_, err := os.Lstat(filePath)
	if err != nil {
		return "", err
	}
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	mem := true
	if memory == "" {
		mem = false
	}
	reader := bufio.NewReader(f)
	readHeader := false
	rowCount := 0
	successCount := 0
	failureCount := 0
	var batch *collection.Batch
	for {
		// read one row from csv (assuming
		record, err := reader.ReadString('\n')
		if err == io.EOF {
			break
		}
		rowCount++
		if err != nil {
			failureCount++
			continue
		}

		record = strings.TrimSuffix(record, "\n")
		record = strings.TrimSuffix(record, "\r")
		if !readHeader {
			columns := strings.Split(record, ",")
			batch, err = api.KVBatch(sessionId, podName, tableName, columns)
			if err != nil {
				return "", err
			}

			err = batch.Put(collection.CSVHeaderKey, []byte(record), false, mem)
			if err != nil {
				failureCount++
				readHeader = true
				continue
			}
			readHeader = true
			successCount++
			continue
		}

		key := strings.Split(record, ",")[0]
		err = batch.Put(key, []byte(record), false, mem)
		if err != nil {
			failureCount++
			continue
		}
		successCount++
	}
	_, err = batch.Write("")
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("csv file loaded in to kv table (%s) with total:%d, success: %d, failure: %d rows", tableName, rowCount, successCount, failureCount), nil
}

func KVSeek(sessionId, podName, tableName, start, end string, limit int64) error {
	_, err := api.KVSeek(sessionId, podName, tableName, start, end, limit)
	return err
}

func KVSeekNext(sessionId, podName, tableName string) (string, error) {
	_, key, data, err := api.KVGetNext(sessionId, podName, tableName)
	if err != nil {
		return "", err
	}
	d := map[string]interface{}{}
	d["key"] = key
	d["value"] = data
	resp, _ := json.Marshal(data)
	return string(resp), nil
}

func DocNewStore(sessionId, podName, tableName, simpleIndexes string, mutable bool) error {
	indexes := make(map[string]collection.IndexType)
	if simpleIndexes != "" {
		idxs := strings.Split(simpleIndexes, ",")
		for _, idx := range idxs {
			nt := strings.Split(idx, "=")
			if len(nt) != 2 {
				return fmt.Errorf("invalid argument")
			}
			switch nt[1] {
			case "string":
				indexes[nt[0]] = collection.StringIndex
			case "number":
				indexes[nt[0]] = collection.NumberIndex
			case "map":
				indexes[nt[0]] = collection.MapIndex
			case "list":
				indexes[nt[0]] = collection.ListIndex
			case "bytes":
			default:
				return fmt.Errorf("invalid indexType")
			}
		}
	}
	return api.DocCreate(sessionId, podName, tableName, indexes, mutable)
}

func DocList(sessionId, podName string) (string, error) {
	collections, err := api.DocList(sessionId, podName)
	if err != nil {
		return "", err
	}
	resp, _ := json.Marshal(collections)
	return string(resp), err
}

func DocOpen(sessionId, podName, tableName string) error {
	return  api.DocOpen(sessionId, podName, tableName)
}

func DocCount(sessionId, podName, tableName, expression string) (string, error) {
	count, err := api.DocCount(sessionId, podName, tableName, expression)
	if err != nil {
		return "", err
	}
	resp, _ := json.Marshal(count)
	return string(resp), err
}

func DocDelete(sessionId, podName, tableName string) error {
	return api.DocDelete(sessionId, podName, tableName)
}

func DocFind(sessionId, podName, tableName, expression string, limit int) (string, error) {
	count, err := api.DocFind(sessionId, podName, tableName, expression, limit)
	if err != nil {
		return "", err
	}
	resp, _ := json.Marshal(count)
	return string(resp), err
}

func DocEntryPut(sessionId, podName, tableName, value string) error {
	return api.DocPut(sessionId, podName, tableName, []byte(value))
}

type DocGetResponse struct {
	Doc []byte `json:"doc"`
}

func DocEntryGet(sessionId, podName, tableName, id string) (string, error) {
	data, err := api.DocGet(sessionId, podName, tableName, id)
	if err != nil {
		return "", err
	}
	var getResponse DocGetResponse
	getResponse.Doc = data

	resp, _ := json.Marshal(getResponse)
	return string(resp), err
}

func DocEntryDelete(sessionId, podName, tableName, id string) error {
	return api.DocDel(sessionId, podName, tableName, id)
}

func DocLoadJson(sessionId, podName, tableName, filePath string) (string, error) {
	_, err := os.Lstat(filePath)
	if err != nil {
		return "", err
	}
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	reader := bufio.NewReader(f)

	rowCount := 0
	successCount := 0
	failureCount := 0
	docBatch, err := api.DocBatch(sessionId, podName, tableName)
	for {
		// read one row from csv (assuming
		record, err := reader.ReadString('\n')
		if err == io.EOF {
			break
		}
		rowCount++
		if err != nil {
			failureCount++
			continue
		}

		record = strings.TrimSuffix(record, "\n")
		record = strings.TrimSuffix(record, "\r")

		err = api.DocBatchPut(sessionId, podName, []byte(record), docBatch)
		if err != nil {
			failureCount++
			continue
		}
		successCount++
	}
	err = api.DocBatchWrite(sessionId, podName, docBatch)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("json file loaded in to document db (%s) with total:%d, success: %d, failure: %d rows", tableName, rowCount, successCount, failureCount), nil
}

func DocIndexJson(sessionId, podName, tableName, filePath string) error {
	return api.DocIndexJson(sessionId, podName, tableName, filePath)
}
