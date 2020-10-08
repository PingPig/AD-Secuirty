# 通过机器学习来检测Powershell恶意行为

## 讲在前面

国内外的各大厂商以及各类研究员多年来对在网络威胁中使用Powershell进行渗透的行为做了不同形式的报告，那么，为什么Poweshell在近几年的渗透中很受攻击中追捧呢，最大的特点就是Powershell的灵活性和丰富的功能使常规检测形同虚设。这篇文章在火眼（FireEye）的通过机器学习来检测Powershell恶意行为研究基础上进行部分修改后展示。

通过这篇文章，读者将会简单学习到：

* 为什么传统的“基于签名”或“基于规则”的检测引擎检测Powershell的威胁会遇到瓶颈
* 如何使用自然语言处理（NLP）来应对这一挑战
* 如何检测混淆了的Powershell命令

## 瓶颈问题的背景

Powershell是近些年受攻击者追捧的最受欢迎的工具之一，通过火眼的威胁动态威胁情报（DTI）云收集的数据显示，恶意Powershell攻击在2017年全年不断增加。

![](https://img-blog.csdnimg.cn/20201008140730838.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  
  


**注意：**  


这里读者可以参考[PowerShell攻击中使用](https://www.blackhat.com/docs/us-14/materials/us-14-Kazanciyan-Investigating-Powershell-Attacks-WP.pdf)的[战术，技术和程序（TTP）](https://www.blackhat.com/docs/us-14/materials/us-14-Kazanciyan-Investigating-Powershell-Attacks-WP.pdf)，以及磁盘，日志和内存中因使用PowerShell恶意而产生的取证伪影  


我们以某个恶意Powershell命令举例：

![](https://img-blog.csdnimg.cn/20201008141026433.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1BpbmdfUGln,size_16,color_FFFFFF,t_70)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


> * -NoProfile  // 在Powershell启动时不执行当前用户导入的配置文件内的配置脚本
> * -NonI //NonInteractive的简写，表示不会向用户显示交互式提示。
> * -W Hidden //WindowStyle Hidden”的简写，表示PowerShell会话窗口应以隐藏方式启动。
> * -Exec Bypass //ExecutionPolicy Bypass”的简写，它禁用当前PowerShell会话的执行策略（默认情况下不允许执行）。应该注意的是，执行策略并不是安全边界。
> * -encodedcommand //后面跟base64编码的命令

让我们看看base64解析后的内容

![](https://img-blog.csdnimg.cn/20201008141516732.png)![](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)​  


有趣的是，解码后的命令将启动隐式的无文件网络访问和远程内容执行！

> * IEX是Invoke-Expression cmdlet的别名，它将执行本地计算机上提供的命令。
> * cmdlet创建一个.NET Framework或COM对象，这里为实例net.webclient对象。
> * downloadstring将下载从&lt;URL&gt;的内容到存储器缓冲器中（然后IEX执行）

### 攻击者偏爱Powershell的原因有如下几个

> 1. Powershell是Microsoft Windows默认的强大的系统管理工具
> 2. 大多数攻击者可以直接利用Powershell来编写恶意代码，而无需安装其他恶意二进制文件，这样可以将脚本大小压缩至最小
> 3. Powershell灵活的语法给基于签名的检测规则带来了复杂的挑战

### 从经济学的角度看

* 攻击者修改Powershell以绕过“基于签名”的检测引擎的成本非常低，尤其是在使用[开源的代码混淆工具](https://www.fireeye.com/blog/threat-research/2017/07/revoke-obfuscation-powershell.html)时。
* 防守方在针对爆发新威胁时更新“基于签名”的检测引擎的规则时，非常耗时间，并且这个工作还只限于专家，普通安全人员难以驾驭。

## 用自然语言处理（NLP）检测恶意Powershell

首次提出该问题是微软自己，当他们意识到Powershell会被攻击者用来玩新花样时，他们做出了应对：[使用深度学习来防御和检测Powershell](https://www.microsoft.com/security/blog/2019/09/03/deep-learning-rises-new-methods-for-detecting-malicious-powershell/)

读者也可以参考这篇由国内译者翻译过来的译文：[利用深度学习检测恶意PowerShell](https://www.freebuf.com/articles/network/213619.html)

同时，我们也可以参考火眼的[文章](https://www.fireeye.com/blog/threat-research/2018/07/malicious-powershell-detection-via-machine-learning.html)，火眼在这上面已经开发出了商业产品  


## PowerShell机器学习检测引擎带来的独特价值包括：  

* 机器学习模型自动从策划的语料库中学习恶意模式。与传统的基于布尔表达式和正则表达式的检测签名规则引擎相比，NLP模型具有较低的运行成本并显着减少了安全内容的发布时间。
* 该模型通过某些模式的隐式学习的非线性组合对未知的PowerShell命令执行概率推断，从而增加了攻击者绕过的成本。

这项创新的最终价值是随着更广泛的威胁格局而发展，并在对手之上建立竞争优势。

