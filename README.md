## Zabbix 2.2.6 new item web.check 
#### Overview
* With new item you can check several availability aspects of web sites via HTTP GET requests.
* Based on curl.
* New item has similar functionality as classic [web scenario](https://www.zabbix.com/documentation/2.2/manual/web_monitoring) + more.
* Scalable number of pre-forked instances of pollers for web.check items. Number of processes can be configured in zabbix server config by StartPollersWeb directive.
* Scalable timeout for web.check poller process. Timeout can be configured by PollerWebTimeout directive.

#### Advantages over classical web monitoring:
* If anything goes wrong while item processing data, item will return what exactly goes wrong via returned value (see details bellow).
* On success item return response code or time.
* You can specify via parameters IP and/or HTTP host header field (one IP vhost problem)
* You can specify more than one match regexp pattern (up to 5).
* You can check only http headers + search regexp match patterns on that header.
* You can check more response times not only total time.
* You can check images.
* Better performance and system resource impact.

#### Disadvantages:
* Does not support POST data 
* Does not collect at once (one HTTP request): response code, download speed, response time.

#### Items:
##### `web.check[<required response>,<ip/dns>,<port>,<http host>,<uri>,<timeout>,<matchstr1>, ... ,<matchstr5>]`
-get request focused on body. Return response code on success. If <required response> does not match return code of web page then return response code. Return error code on failure.
##### `web.check.bauth[<required response>,<ip/dns>,<port>,<http host>,<uri>,<timeout>,<user:passwd>,<matchstr1>,...]`
-get request focused on body with http basic auth. If <required response> does not match return code of web page then return response code. Return
error code on failure.
##### `web.check.header[<required response>,<ip/dns>,<port>,<http host>,<uri>,<timeout>,<matchstr1>, ..., <matchstr5>]`
-get request focused on header. Check only header for match patterns. If <required response> does not match return code of web page then return response code. Return error code on failure.
##### `web.check.img[<ip/dns>,<port>,<http host>,<uri>,<timeout>]`
-get request focused on header content-type: image*. Response content type must contain image substring. Return response code on success, otherwise error code.
##### `web.check.time[<ip/dns>,<port>,<http host>,<uri>,<timeout>,<time pattern>]`
-get request focused on response times. Return response time in miliseconds on success, otherwise error code.

#### About params:

#####	REQUIRED RESPONSE
- Required parameter. Must be set or left blank.
- Required http response code.
- If web page return different code as required then item return response code and stop processing next key checks (regexp search patterns).
- If parameter is left blank, default value will be 200 http response code.

#####	IP/DNS
- Required parameter. Must be set or left blank.
- Ip or dns of website.
- If parameter is left blank, default value will be primary agent interface.
- If parameter is DNS, default http host parameter will be same as DNS.
- Example: "example.com" or "192.168.0.1" or ""

#####	PORT
- Required parameter. Must be set or left blank.
- Port of website.
- Default value is 80.
- If parameter is 443 item perform https request.
- Allowed range: 0 - 65535

#####	HTTP HOST
- Required parameter. Must be set or left blank.
- Http host header field.
- Default value is "".
- If DNS parameter is set, default HTTP HOST value will be same as DNS name. You can override this by specify HTTP HOST parameter or by keyword "none".
- Example: "google.com" or "none" or ""

#####	URI
- Required parameter. Must be set or left blank.
- Uri to connect to and retrieve data.
- Default value is "/".
- Example "/uri/request" or "uri/request" or ""

#####	TIMEOUT
- Required parameter. Must be set or left blank.
- Item will not spend more than the set amount of seconds on processing the request.
- Default value is 10 seconds.
- Allowed range: 1 - (PollerWebTimeout - 1).

##### MATCHSTR
- Optional parameter.
- Required regular expressions pattern.
- Default none.
- If retrieved content (HTML) does not match required pattern then the item will return error code. If parameter is empty then no regexp check is performed.
- Maximum number of regular expression is 5.
- Example: "<html" or "" or not specified

##### USER:PASSWD
- Required parameter. Must be set.
- For basic access authentication.
- Specify parameter in form of "username:password"
- Default none.

##### TIME PATTERN
- Required parameter. Must be set.
- Allowed patterns: connect, appconnect, pretrans, starttrans, total, redir
`|--CONNECT - Time it took from the start until the connect to the remote host was completed`
`|--|--APPCONNECT - Time it took from the start until the SSL connect/handshake with the remote host was completed.`
`|--|--|--PRETRANSFER - Time it took from the start until the file transfer is just about to begin.`
`|--|--|--|--STARTTRANSFER - Time it took from the start until the first byte is received.`
`|--|--|--|--|--TOTAL - Total time of the request.`
`|--|--|--|--|--|--REDIRECT - Time it took for all redirection steps.`

#### Item return codes:
**0 - 99** - reserved for cURL error. For more detail see: http://curl.haxx.se/libcurl/c/libcurl-errors.html

**100 - 599** - reserved fot http response codes

**600** - dns lookup error. For more details see zabbix server log.

**601** - curl internal error. For more details see zabbix server log.

**602** - regexp does not match. For more details see zabbix server log.

**603** - content type does not match (web.check.img). For more details see zabbix server log.

#### Examples:
```
web.check[200,173.194.112.31,80,www.google.sk,/,2,<html,google] = 200

web.check[200,www.google.sk,80,,/,2] = 200

web.check[200,www.google.sk,443,,/,2] = 200

web.check[200,google.sk,80,,/,2] = 301
error log: Required response code (200) does not match (301) for key web.check[200,google.sk,80,,/,2]

web.check[200,www.google.sk,80,,/,2,match this string] = 602
error log: Required regexp not found "match this string" for key web.check[200,www.google.sk,80,,/,2,match this string]

web.check[200,www.google.sk,1234,,1,] = 28 = OPERATION_TIMEDOUT
error log: Error during curl_easy_perform: Timeout was reached for key web.check[200,www.google.sk,1234,,1,]

web.check[blah,www.google.sk,80,www.google.sk,/,2] = Invalid RESPONSE CODE parameter
error log: item web.check[blah,www.google.sk,80,www.google.sk,/,2] became not supported: Invalid RESPONSE CODE parameter

web.check[200,www.google.sk,] = Invalid  number of parameters
error log: item web.check[200,www.google.sk,] became not supported: Invalid  number of parameters`
```
#### Installation
1. Download zabbix 2.2.6 stable (http://sourceforge.net/projects/zabbix/files/ZABBIX%20Latest%20Stable/2.2.6/zabbix-2.2.6.tar.gz)
2. tar xvzf zabbix-2.2.6.tar.gz
3. cd zabbix-2.2.6
4. patch -p2 < zabbix-2.2.6.patch
5. autoreconf
6. ./configure --enable-server --with-libcurl ...
5. make install

or

1. git clone https://github.com/dojci/zabbix-2.2.6_webcheck
2. cd zabbix-2.2.6_webcheck/zabbix-2.2.6_patched
3. ./configure --enable-server --with-libcurl ...
4. make install

#### TODO:
- Oneshot parameter for: proctol, dns/ip, port, uri (http://example.com:80)
