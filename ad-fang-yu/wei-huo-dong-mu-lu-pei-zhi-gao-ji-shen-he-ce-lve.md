# 为活动目录配置高级审核策略

## 讲在前面

在域内我们需要开启相关得审核策略才能获得某些特殊事件得日志信息，所以我们在做分析的时候对于那些日志的开启需要有一个概念，笔者如下展示笔者目前所需的日志项  


## 高级审核策略需要开启的项目 

### 账户登录 

* 审核凭据验证（成功和失败） 
* Kerberos 服务票证操作（成功和失败） 
* Kerberos 身份验证服务（成功和失败） 
* 其他帐户登录事件（成功和失败） 

![](https://img-blog.csdnimg.cn/20201026201541889.png)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


### 账户管理 

* 审核应用程序组管理（成功和失败） 
* 审核计算机帐户管理（成功和失败） 
* 审核通讯组管理（成功和失败） 
* 审核其他帐户管理事件（成功和失败） 
* 审核安全组管理（成功和失败） 
* 审核用户帐户管理（成功和失败） 

![](https://img-blog.csdnimg.cn/20201026201552452.png)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


### 详细跟踪 

* 审核进程创建（成功和失败） 
* 审核进程终止（成功和失败） 
* 审核RPC 事件（成功和失败） 

![](https://img-blog.csdnimg.cn/20201026201919254.png)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


### DS访问 

* 审核详细的目录服务复制（成功和失败） 
* 审核目录服务访问（成功和失败） 
* 审核目录服务更改（成功和失败） 
* 审核目录服务复制（成功和失败） 

![](https://img-blog.csdnimg.cn/20201026202026320.png)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


### 登录/注销 

* 审核帐户锁定（成功和失败） 
* 审核注销（成功和失败） 
* 审核登录（成功和失败） 
* 审核网络策略服务器（成功和失败） 
* 审核其他登录/注销事件（成功和失败） 
* 审核特殊登录（成功和失败） 

![](https://img-blog.csdnimg.cn/20201026202113971.png)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


### 对象访问 

* 审核详细的文件共享（成功和失败） 
* 审核文件共享（成功和失败） 
* 审核文件系统（成功和失败） 
* 审核筛选平台连接（无审核） 
* 审核筛选平台数据包丢弃（无审核） 
* 审核其他对象访问事件（成功和失败） 
* 审核注册表（成功和失败） 
* 审核SAM（成功和失败） 

![](https://img-blog.csdnimg.cn/20201026202208812.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


### 策略更改 

* 审核审核策略更改（成功和失败） 
* 审核身份验证策略更改（成功和失败） 
* 审核授权策略更改（成功和失败） 
* 审核筛选平台策略更改（成功和失败） 
* 审核其他策略更改事件（成功和失败） 

![](https://img-blog.csdnimg.cn/20201026202457202.png)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


### 特权使用

* 审核非敏感权限使用（成功和失败） 
* 审核其他权限使用事件（成功和失败） 
* 审核敏感权限使用（成功和失败） 

![](https://img-blog.csdnimg.cn/20201026202543530.png)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


### 系统

* 审核其他系统事件（成功和失败） 
* 审核安全状态更改（成功和失败） 
* 审核安全系统扩展（成功和失败） 
* 审核系统完整性（成功和失败） 

![](https://img-blog.csdnimg.cn/20201026202611276.png)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​

