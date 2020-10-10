# Kerberos协议产生的委派攻击

## 讲在前面

一味的对知识的搬运或生搬硬抄要么就是对其理解并不多，要么就是读了文章却不知实际如何操作。接下来的文章都相对来说不是很简单，笔者尽量以言简意赅短小精悍的语句描述。  


目前所公布的所有研究文章都指出了存在非约束委派攻击、约束委派攻击以及基于资源的约束委派攻击。同时我们必须要明白Kerberos扩展出的两个协议S4U2SELF和S4U2PROXY  


## 委派

在域中如果出现账户A使用Kerberos身份验证访问域中的服务B，而B再利用A的身份去请求服务C，这个过程就可以理解为委派，其中理解成A委派B请求C，B为受委派账户。  


**注意：**

受委派账户只能是机器账户或服务账户

## 非约束委派

**简述：**常被利用进行凭据盗取

**举例：**

这里我们参考：

[Kerberos协议探索](https://www.freebuf.com/articles/network/198381.html)中非约束委派的小例子，具体如何发挥请读者自行探讨。  


## 约束委派

简述：需要理解S4U2SELF和S4U2PROXY两个扩展协议，因非约束委派的不安全性微软扩展出这两个协议，配置后来约束委派。

**举例：**

这里我们参考：

[Kerberos协议探索](https://www.freebuf.com/articles/network/198381.html)中非约束委派的小例子，具体如何发挥请读者自行探讨。

基于资源的约束委派

简述：传统的约束委派S4U2Self返回的票据一定是可转发的，如果不可转发那么S4U2Proxy将失败；但是基于资源的约束委派不同，就算S4U2Self返回的票据不可转发，S4U2Proxy也是可以成功，并且S4U2Proxy返回的票据总是可转发。

这里参考：

[滥用基于资源约束委派](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)

[基于资源的约束委派利用](https://blog.csdn.net/a3320315/article/details/107096250/)

[基于资源的约束委派利用2](https://xz.aliyun.com/t/7454#toc-1)  


关于扩展协议笔者暂且搁置，这里提供优秀介绍文章：

[内网学习之域内三大协议](https://daiker.gitbook.io/windows-protocol/kerberos/2#1-fei-yue-shu-wei-pai)

S4U2SELF

S4U2PROXY

