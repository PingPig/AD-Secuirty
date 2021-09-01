# 什么是ATA

## 讲在前面：

> 本系列文章是笔者在国外研究员的基础上进行翻译并按照其思路进行实际测试，并做出笔者的自我总结和研究结论。笔者依旧力求将该知识点通过讲人话的形式表达出来，希望读者能够通过该系列文章，了解什么是ATA、它的作用、它的检测方式、它的绕过方式等一系列该产品基本知识。

## ATA是什么

**简述：产品全称【**Advanced Threat Analytics】又名【高级威胁分析】，是微软一款防护域控制器的产品， 用于检测对 Active Directory 的一系列攻击，目前最新版本是1.9版，但微软已经停止对其产品的继续更新和维护。

**总结：**

* 高级威胁分析 \(ATA\) 是一个本地平台。
* ATA是防护域控的产品。
* 主要是针对流量、日志来进行处理得出分析结果。

## ATA做什么

ATA有两个数据来源。一是流量，二是日志

**解释：**

* 流量：利用其专有的网络解析引擎来捕获和解析多种协议（例如Kerberos、DNS、RPC、NTLM等）网络流量，方式有如下两种：

> * 在域控制器和 DNS 服务器到 ATA 网关**。**
> * 在域控制器上部署 ATA 轻量级网关 \(LGW\) ATA。

* 日志：可以通过如下三种方式来接收事件和日志：

> * SIEM 集成。
> * Windows 事件转发 \(WEF\)。
> * Windows 事件管理器。

ATA和ATP的区别以及相同之处





[https://blog.ahasayen.com/azure-advanced-threat-protection-azure-atp-vs-ata/](https://blog.ahasayen.com/azure-advanced-threat-protection-azure-atp-vs-ata/)

## 参考文章：



