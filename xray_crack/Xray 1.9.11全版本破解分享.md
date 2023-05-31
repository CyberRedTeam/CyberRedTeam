xray 是一款功能强大的安全评估工具，由多名经验丰富的一线安全从业者呕心打造而成。
### 快速使用
1.  使用基础爬虫爬取并对爬虫爬取的链接进行漏洞扫描

    ```bash
    xray webscan --basic-crawler http://example.com --html-output vuln.html
    ```
    
2.  使用 HTTP 代理进行被动扫描
    
    ```bash
    xray webscan --listen 127.0.0.1:7777 --html-output proxy.html
    ```
    
    设置浏览器 http 代理为 `http://127.0.0.1:7777`，就可以自动分析代理流量并扫描。
    
    > 如需扫描 https 流量，请阅读下方文档 `抓取 https 流量` 部分
    
3.  只扫描单个 url，不使用爬虫
    
    ```bash
    xray webscan --url http://example.com/?a=b --html-output single-url.html
    ```
    
4.  手动指定本次运行的插件
    
    默认情况下，将会启用所有内置插件，可以使用下列命令指定本次扫描启用的插件。
    
    ```bash
    xray webscan --plugins cmd-injection,sqldet --url http://example.com
    xray webscan --plugins cmd-injection,sqldet --listen 127.0.0.1:7777
    ```
    
5.  指定插件输出
    
    可以指定将本次扫描的漏洞信息输出到某个文件中:
    
    ```bash
    xray webscan --url http://example.com/?a=b \
    --text-output result.txt --json-output result.json --html-output report.html
    ```
进阶使用请查看：https://docs.xray.cool/
### 更新内容
该版本为 用友NC NCMessageServlet反序列化漏洞 注入漏洞 的应急版本，相较上个版本，除了添加了一个POC外，未改动其他内容。
```bash
./xray ws --poc poc-yaml-yongyou-nc-ncmessageservlet-rce --url http://example.com
```
## 工具分享
团队使用无后门，关注 私信xray 即可获取
