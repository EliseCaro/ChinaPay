package service

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"golang.org/x/crypto/pkcs12"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

type ChinaPayService struct{}

/**********************************************************支付Start********************************************************/

// PayTest 支付demo
// new(service.ChinaPayService).PayTest()
func (service *ChinaPayService) PayTest() {
	urlsFor := "https://tzf.chinapay.com/cofcoko/bgTransGet"
	paramsMap := map[string]string{
		"Version":       "20140728",
		"AccessType":    "0",
		"MerId":         "商户号",
		"MerOrderNo":    fmt.Sprintf(`%s0000001`, service.GetTimeLocal(`20060102150405`)),
		"TranDate":      service.GetTimeLocal(`20060102`),
		"TranTime":      service.GetTimeLocal(`150405`),
		"OrderAmt":      "1",
		"TranType":      "0009",
		"BusiType":      "0001",
		"CurryNo":       "CNY",
		"OrderReserved": "{\"OrderType\":\"0001\",\"qrPattern\":\"link\"}",
	}
	if erron, sign := service.SignAction(paramsMap); erron == nil {
		paramsMap["Signature"] = sign
		if err, data := service.RequestPost(urlsFor, paramsMap); err == nil {
			fmt.Println(data)
		} else {
			fmt.Println(err)
		}
	} else {
		fmt.Println(erron)
	}
}

// GetPostParams 发起post 组装参数
func (service *ChinaPayService) GetPostParams(params map[string]string) url.Values {
	value := url.Values{}
	for key, val := range params {
		value.Set(key, val)
	}
	return value
}

// StrToJson 将字符串解析成Map
func (service *ChinaPayService) StrToJson(urls url.Values) (error, map[string]interface{}) {
	maps := map[string]interface{}{}
	for key, _ := range urls {
		maps[key] = urls.Get(key)
	}
	return nil, maps
}

// RequestPost 发起post
func (service *ChinaPayService) RequestPost(urls string, params map[string]string) (error, map[string]interface{}) {
	resp, err := http.PostForm(urls, service.GetPostParams(params))
	if err != nil {
		return errors.New(fmt.Sprintf(`获取支付二维码发起请求失败；%s`, err.Error())), map[string]interface{}{}
	}
	defer func(Body io.ReadCloser) { _ = Body.Close() }(resp.Body)
	if body, err := ioutil.ReadAll(resp.Body); err != nil {
		return errors.New(fmt.Sprintf(`获取支付二维码写入IO失败；%s`, err.Error())), map[string]interface{}{}
	} else {
		if urlVal, erron := url.ParseQuery(string(body)); erron == nil {
			return service.StrToJson(urlVal)
		} else {
			return errors.New(fmt.Sprintf(`获取支付二维码解析URL参数失败；%s`, erron.Error())), map[string]interface{}{}
		}
	}
}

// GetTimeLocal 获取本地时间
// 2006-01-02 15:04:05
func (service *ChinaPayService) GetTimeLocal(f string) string {
	return time.Now().Format(f)
}

// GetPfxLocal 获取pfx文件路径以及密码
func (service *ChinaPayService) GetPfxLocal() (string, string) {
	pfxname := "737272206270001.pfx"
	pfx := fmt.Sprintf(`/package/csdnRes/static/secret/%s`, pfxname)
	return pfx, "123456"
}

// SignAction 开始签名
func (service *ChinaPayService) SignAction(item map[string]string) (error, string) {
	dataStr := service.getURLParam(item, true)
	pfx, pwd := service.GetPfxLocal()
	keyStore, erron := service.getKeyStore(pfx, pwd)
	if erron != nil || keyStore == nil {
		return erron, ""
	} else {
		sign, erron := service.SignSHA512(dataStr, keyStore)
		if erron != nil {
			return erron, ""
		}
		return nil, base64.StdEncoding.EncodeToString(sign)
	}
}

// SignSHA512 签名SignSHA512字符串
func (service *ChinaPayService) SignSHA512(data string, privateKey *rsa.PrivateKey) ([]byte, error) {
	h := crypto.Hash.New(crypto.SHA512)
	h.Write([]byte(data))
	hashed := h.Sum(nil)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA512, hashed)
	if err != nil {
		return []byte{}, errors.New(fmt.Sprintf("Error from signing: %s\n", err))
	}
	return signature, nil
}

// 获取公钥证书
func (service *ChinaPayService) getKeyStore(signFile, signFilePwd string) (*rsa.PrivateKey, error) {
	var (
		fs     *os.File
		erron  error
		bytes  []byte
		blocks []*pem.Block
	)
	if fs, erron = os.Open(signFile); erron != nil {
		return nil, erron
	}
	defer func(fs *os.File) { _ = fs.Close() }(fs)
	if bytes, erron = ioutil.ReadAll(fs); erron != nil {
		return nil, erron
	}
	if blocks, erron = pkcs12.ToPEM(bytes, signFilePwd); erron != nil {
		return nil, errors.New("PKCS12证书解密错误~")
	}
	if privateKey, erron := x509.ParsePKCS1PrivateKey(blocks[0].Bytes); erron != nil {
		return nil, erron
	} else {
		return privateKey, nil
	}
}

// getURLParam 组装请求参数
func (service *ChinaPayService) getURLParam(item map[string]string, isSort bool) string {
	var uRLParam string
	var arrayList []string
	for key, val := range item {
		arrayList = append(arrayList, fmt.Sprintf(`%s=%s`, key, val))
	}
	if isSort { // 排序
		sort.Strings(arrayList)
	}
	for _, val := range arrayList {
		uRLParam += fmt.Sprintf(`&%s`, val)
	}
	return strings.TrimLeft(uRLParam, "&")
}

/**********************************************************支付demo********************************************************/
