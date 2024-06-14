# WeeBot Python

## 快速开始

### 环境安装及检查

1. 微信版本 3.9.10.27
2. Python版本 3.7+

### 安装依赖

```shell
pip install frida
pip install frida-tools
```

### 启动

```shell
python main.py
```

## 接口说明

- 所有接口只支持post方法
- 全部使用json格式
- 请求地址： http://127.0.0.1:19088 
- 返回结构的json格式：  

 ``` javascript
  {
    "code": 1,
    "data": {},
    "msg": "success"
}
```

### 获取登录用户信息

#### 接口功能
> 获取登录用户信息

#### 接口地址
> /api/userInfo

#### HTTP请求方式
> POST  JSON

#### 请求参数
|参数|必选|类型|说明|
|---|---|---|---|

#### 返回字段
|返回字段|字段类型|说明                              |
|---|---|---|
|code|int|返回状态,1 成功, 0失败|
|result|string|成功提示|
|data|object|响应内容|
|&#8194;&#8194;account|string|账号|
|&#8194;&#8194;headImage|string|头像|
|&#8194;&#8194;city|string|城市|
|&#8194;&#8194;country|string|国家| 
|&#8194;&#8194;currentDataPath|string|当前数据目录,登录的账号目录|
|&#8194;&#8194;dataSavePath|string|微信保存目录|
|&#8194;&#8194;mobile|string|手机|
|&#8194;&#8194;name|string|昵称|
|&#8194;&#8194;province|string|省|
|&#8194;&#8194;wxid|string|wxid|
|&#8194;&#8194;signature|string|个人签名|
|&#8194;&#8194;dbKey|string|数据库的SQLCipher的加密key，可以使用该key配合decrypt.py解密数据库

#### 接口示例
入参：
``` javascript
```
响应：
``` javascript
{
    "code": 1,
    "data": {
        "account": "xxx",
        "city": "Zhengzhou",
        "country": "CN",
        "currentDataPath": "C:\\WeChat Files\\wxid_xxx\\",
        "dataSavePath": "C:\\wechatDir\\WeChat Files\\",
        "dbKey": "965715e30e474da09250cb5aa047e3940ffa1c8f767c4263b132bb512933db49",
        "headImage": "https://wx.qlogo.cn/mmhead/ver_1/MiblV0loY0GILewQ4u2121",
        "mobile": "13949175447",
        "name": "xxx",
        "province": "Henan",
        "signature": "xxx",
        "wxid": "wxid_22222"
    },
    "msg": "success"
}
```

### 获取联系人列表

#### 接口功能
> 获取登录用户信息

#### 接口地址
> [/api/userInfo](/api/userInfo)

#### HTTP请求方式
> POST  JSON

#### 请求参数
|参数|必选|类型|说明|
|---|---|---|---|


#### 返回字段
|返回字段|字段类型|说明                              |
|---|---|---|
|code|int|返回状态,1 成功, 0失败|
|result|string|成功提示|
|data|object|响应内容|
|&#8194;&#8194;account|string|账号|
|&#8194;&#8194;headImage|string|头像|
|&#8194;&#8194;city|string|城市|
|&#8194;&#8194;country|string|国家| 
|&#8194;&#8194;currentDataPath|string|当前数据目录,登录的账号目录|
|&#8194;&#8194;dataSavePath|string|微信保存目录|
|&#8194;&#8194;mobile|string|手机|
|&#8194;&#8194;name|string|昵称|
|&#8194;&#8194;province|string|省|
|&#8194;&#8194;wxid|string|wxid|
|&#8194;&#8194;signature|string|个人签名|
|&#8194;&#8194;dbKey|string|数据库的SQLCipher的加密key，可以使用该key配合decrypt.py解密数据库

#### 接口示例
入参：
``` javascript
```
响应：
``` javascript
{
    "code": 1,
    "data": {
        "account": "xxx",
        "city": "Zhengzhou",
        "country": "CN",
        "currentDataPath": "C:\\WeChat Files\\wxid_xxx\\",
        "dataSavePath": "C:\\wechatDir\\WeChat Files\\",
        "dbKey": "965715e30e474da09250cb5aa047e3940ffa1c8f767c4263b132bb512933db49",
        "headImage": "https://wx.qlogo.cn/mmhead/ver_1/MiblV0loY0GILewQ4u2121",
        "mobile": "13949175447",
        "name": "xxx",
        "province": "Henan",
        "signature": "xxx",
        "wxid": "wxid_22222"
    },
    "msg": "success"
}
```

### 发送消息

#### 接口功能
> 获取登录用户信息

#### 接口地址
> /api/userInfo

#### HTTP请求方式
> POST  JSON

#### 请求参数
|参数|必选|类型|说明|
|---|---|---|---|

#### 返回字段
|返回字段|字段类型|说明                              |
|---|---|---|
|code|int|返回状态,1 成功, 0失败|
|result|string|成功提示|
|data|object|响应内容|
|&#8194;&#8194;account|string|账号|
|&#8194;&#8194;headImage|string|头像|
|&#8194;&#8194;city|string|城市|
|&#8194;&#8194;country|string|国家| 
|&#8194;&#8194;currentDataPath|string|当前数据目录,登录的账号目录|
|&#8194;&#8194;dataSavePath|string|微信保存目录|
|&#8194;&#8194;mobile|string|手机|
|&#8194;&#8194;name|string|昵称|
|&#8194;&#8194;province|string|省|
|&#8194;&#8194;wxid|string|wxid|
|&#8194;&#8194;signature|string|个人签名|
|&#8194;&#8194;dbKey|string|数据库的SQLCipher的加密key，可以使用该key配合decrypt.py解密数据库

#### 接口示例
入参：
``` javascript
```
响应：
``` javascript
{
    "code": 1,
    "data": {
        "account": "xxx",
        "city": "Zhengzhou",
        "country": "CN",
        "currentDataPath": "C:\\WeChat Files\\wxid_xxx\\",
        "dataSavePath": "C:\\wechatDir\\WeChat Files\\",
        "dbKey": "965715e30e474da09250cb5aa047e3940ffa1c8f767c4263b132bb512933db49",
        "headImage": "https://wx.qlogo.cn/mmhead/ver_1/MiblV0loY0GILewQ4u2121",
        "mobile": "13949175447",
        "name": "xxx",
        "province": "Henan",
        "signature": "xxx",
        "wxid": "wxid_22222"
    },
    "msg": "success"
}
```