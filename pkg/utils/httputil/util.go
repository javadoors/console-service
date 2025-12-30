/*
 * Copyright (c) 2024 Huawei Technologies Co., Ltd.
 * openFuyao is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

package httputil

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"sync"

	"k8s.io/client-go/kubernetes"

	"console-service/pkg/constant"
	"console-service/pkg/utils/k8sutil"
	"console-service/pkg/zlog"
)

// ResponseJson Http Response
type ResponseJson struct {
	Code int32  `json:"code,omitempty"`
	Msg  string `json:"msg,omitempty"`
	Data any    `json:"data,omitempty"`
}

// GetResponseJson get restful response struct
func GetResponseJson(code int32, msg string, data any) *ResponseJson {
	return &ResponseJson{
		Code: code,
		Msg:  msg,
		Data: data,
	}
}

// GetDefaultSuccessResponseJson get default success response json
func GetDefaultSuccessResponseJson() *ResponseJson {
	return &ResponseJson{
		Code: constant.Success,
		Msg:  "success",
		Data: nil,
	}
}

// GetDefaultClientFailureResponseJson get default failure response json
func GetDefaultClientFailureResponseJson() *ResponseJson {
	return &ResponseJson{
		Code: constant.ClientError,
		Msg:  "bad request",
		Data: nil,
	}
}

// GetDefaultServerFailureResponseJson get default failure response json
func GetDefaultServerFailureResponseJson() *ResponseJson {
	return &ResponseJson{
		Code: constant.ServerError,
		Msg:  "remote server busy",
		Data: nil,
	}
}

// GetParamsEmptyErrorResponseJson get default resource empty response json
func GetParamsEmptyErrorResponseJson() *ResponseJson {
	return &ResponseJson{
		Code: constant.ClientError,
		Msg:  "parameters not found",
		Data: nil,
	}
}

var (
	clientInstance *http.Client
	clientOnce     sync.Once
)

// GetHttpConfig get http config
func GetHttpConfig(enableTLS bool) (*tls.Config, error) {
	dummyConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
	}
	if enableTLS {
		cert, err := tls.LoadX509KeyPair(constant.TLSCertPath, constant.TLSKeyPath)
		if err != nil {
			return dummyConfig, err
		}

		// Load CA cert
		caCert, err := os.ReadFile(constant.CAPath)
		if err != nil {
			return dummyConfig, err
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		// Setup HTTPS client
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS13,
			RootCAs:      caCertPool,
		}, nil
	} else {
		return dummyConfig, nil
	}
}

// GetHttpTransport returns an HTTP transport
func GetHttpTransport(enableTLS bool) (*http.Transport, error) {
	tlsConfig, err := GetHttpConfig(enableTLS)
	if err != nil {
		return nil, err
	}
	return &http.Transport{
		TLSClientConfig: tlsConfig,
	}, nil
}

// GetCustomizedHttpConfigByPath returns a TLS config with optional certs and CA
func GetCustomizedHttpConfigByPath(certPath, keyPath, caPath string) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
	}

	// load certs
	if err := loadClientCert(tlsCfg, certPath, keyPath); err != nil {
		return tlsCfg, err
	}

	// load CA
	if err := loadCA(tlsCfg, caPath); err != nil {
		return tlsCfg, err
	}

	// fallback
	if len(tlsCfg.Certificates) == 0 && tlsCfg.RootCAs == nil {
		tlsCfg.InsecureSkipVerify = true
	}
	return tlsCfg, nil
}

// GetCustomizedHttpConfigByRaw returns a TLS config with optional certs and CA
func GetCustomizedHttpConfigByRaw(skipTLS bool, cert, key, ca []byte) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
	}
	if skipTLS {
		tlsCfg.InsecureSkipVerify = true
		return tlsCfg, nil
	}
	if len(ca) != 0 {
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(ca) {
			return tlsCfg, fmt.Errorf("ca is illegal, failed to load ca for extension component")
		}
		tlsCfg.RootCAs = caCertPool
	} else {
		return tlsCfg, fmt.Errorf("required tls verification but no ca is provided")
	}
	if len(cert) != 0 && len(key) != 0 {
		clientCert, err := tls.X509KeyPair(cert, key)
		if err != nil {
			return tlsCfg, fmt.Errorf("failed to load client certificate/key: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{clientCert}
		return tlsCfg, nil
	}
	if len(cert) != 0 || len(key) != 0 {
		// 防止用户只提供 cert 或 key 其中一个
		return tlsCfg, fmt.Errorf("both cert and key must be provided for client authentication")
	}

	return tlsCfg, nil
}

func loadClientCert(tlsCfg *tls.Config, certPath, keyPath string) error {
	if certPath == "" || keyPath == "" {
		return nil
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("load cert/key: %w", err)
	}
	tlsCfg.Certificates = []tls.Certificate{cert}
	return nil
}

func loadCA(tlsCfg *tls.Config, caPath string) error {
	if caPath == "" {
		return nil
	}
	caCert, err := os.ReadFile(caPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read CA %s: %w", caPath, err)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return fmt.Errorf("append CA %s failed", caPath)
	}
	tlsCfg.RootCAs = caCertPool
	return nil
}

// GetCustomizedHttpTransportByPath returns an HTTP transport
func GetCustomizedHttpTransportByPath(certPath, keyPath, caPath string) (*http.Transport, error) {
	tlsConfig, err := GetCustomizedHttpConfigByPath(certPath, keyPath, caPath)
	if err != nil {
		return &http.Transport{
			TLSClientConfig: tlsConfig,
		}, err
	}
	return &http.Transport{
		TLSClientConfig: tlsConfig,
	}, nil
}

// GetCustomizedHttpTransportByRaw returns an HTTP transport
func GetCustomizedHttpTransportByRaw(skipTLS bool, certData, keyData, caData []byte) (*http.Transport, error) {
	tlsConfig, err := GetCustomizedHttpConfigByRaw(skipTLS, certData, keyData, caData)
	return &http.Transport{
		TLSClientConfig: tlsConfig,
	}, err
}

// IsHttpsEnabled is https enabled
func IsHttpsEnabled() (bool, error) {
	if _, err := os.Stat(constant.TLSCertPath); err != nil {
		if os.IsNotExist(err) {
			zlog.Warnf("tls cert not exist %v, use http", err)
			return false, nil
		} else {
			zlog.Errorf("tls cert exist, but failed accessing file, %v", err)
			return false, err
		}
	}
	return true, nil
}

// GetK8sRootCA get certificate and key from secret
func GetK8sRootCA(client kubernetes.Interface) ([]byte, error) {
	secret, err := k8sutil.GetConfigMap(client, "kube-root-ca.crt",
		constant.ConsoleServiceDefaultNamespace)
	if err != nil {
		return nil, fmt.Errorf("console-service secret not found")
	}

	ca, exists := secret.Data["ca.crt"]

	if !exists {
		return nil, fmt.Errorf("console-service cert and key not found")
	}
	return []byte(ca), nil
}
