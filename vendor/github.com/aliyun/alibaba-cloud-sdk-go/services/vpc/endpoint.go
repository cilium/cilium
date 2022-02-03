package vpc

// EndpointMap Endpoint Data
var EndpointMap map[string]string

// EndpointType regional or central
var EndpointType = "regional"

// GetEndpointMap Get Endpoint Data Map
func GetEndpointMap() map[string]string {
	if EndpointMap == nil {
		EndpointMap = map[string]string{
			"cn-shanghai-internal-test-1": "vpc.aliyuncs.com",
			"cn-beijing-gov-1":            "vpc.aliyuncs.com",
			"cn-shenzhen-su18-b01":        "vpc.aliyuncs.com",
			"cn-beijing":                  "vpc.aliyuncs.com",
			"cn-shanghai-inner":           "vpc.aliyuncs.com",
			"cn-shenzhen-st4-d01":         "vpc.aliyuncs.com",
			"cn-haidian-cm12-c01":         "vpc.aliyuncs.com",
			"cn-hangzhou-internal-prod-1": "vpc.aliyuncs.com",
			"cn-north-2-gov-1":            "vpc.aliyuncs.com",
			"cn-yushanfang":               "vpc.aliyuncs.com",
			"cn-qingdao":                  "vpc.aliyuncs.com",
			"cn-hongkong-finance-pop":     "vpc.aliyuncs.com",
			"cn-qingdao-nebula":           "vpc-nebula.cn-qingdao-nebula.aliyuncs.com",
			"cn-shanghai":                 "vpc.aliyuncs.com",
			"cn-shanghai-finance-1":       "vpc.aliyuncs.com",
			"cn-hongkong":                 "vpc.aliyuncs.com",
			"cn-beijing-finance-pop":      "vpc.aliyuncs.com",
			"cn-wuhan":                    "vpc.aliyuncs.com",
			"us-west-1":                   "vpc.aliyuncs.com",
			"cn-zhangbei":                 "vpc.aliyuncs.com",
			"cn-shenzhen":                 "vpc.aliyuncs.com",
			"cn-zhengzhou-nebula-1":       "vpc-nebula.cn-qingdao-nebula.aliyuncs.com",
			"rus-west-1-pop":              "vpc.aliyuncs.com",
			"cn-shanghai-et15-b01":        "vpc.aliyuncs.com",
			"cn-hangzhou-bj-b01":          "vpc.aliyuncs.com",
			"cn-hangzhou-internal-test-1": "vpc.aliyuncs.com",
			"eu-west-1-oxs":               "vpc-nebula.cn-shenzhen-cloudstone.aliyuncs.com",
			"cn-zhangbei-na61-b01":        "vpc.aliyuncs.com",
			"cn-hangzhou-internal-test-3": "vpc.aliyuncs.com",
			"cn-shenzhen-finance-1":       "vpc.aliyuncs.com",
			"cn-hangzhou-internal-test-2": "vpc.aliyuncs.com",
			"cn-hangzhou-test-306":        "vpc.aliyuncs.com",
			"cn-huhehaote-nebula-1":       "vpc-nebula.cn-qingdao-nebula.aliyuncs.com",
			"cn-shanghai-et2-b01":         "vpc.aliyuncs.com",
			"cn-hangzhou-finance":         "vpc.aliyuncs.com",
			"ap-southeast-1":              "vpc.aliyuncs.com",
			"cn-beijing-nu16-b01":         "vpc.aliyuncs.com",
			"cn-edge-1":                   "vpc-nebula.cn-qingdao-nebula.aliyuncs.com",
			"us-east-1":                   "vpc.aliyuncs.com",
			"cn-fujian":                   "vpc.aliyuncs.com",
			"ap-northeast-2-pop":          "vpc.aliyuncs.com",
			"cn-shenzhen-inner":           "vpc.aliyuncs.com",
			"cn-zhangjiakou-na62-a01":     "vpc.cn-zhangjiakou.aliyuncs.com",
			"cn-hangzhou":                 "vpc.aliyuncs.com",
		}
	}
	return EndpointMap
}

// GetEndpointType Get Endpoint Type Value
func GetEndpointType() string {
	return EndpointType
}
