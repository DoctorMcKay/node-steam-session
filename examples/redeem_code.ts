import {randomBytes} from "crypto";
import {EAuthTokenPlatformType, LoginSession} from "../src";
import {getDataForPlatformType, getSpoofedHostname} from "../src/helpers";

let webCookies = [
  'steamCountry=US%7Ce3a429901b56974b144d3b420e1973d0',
  'steamLoginSecure=76561199481476887%7C%7CeyAidHlwIjogIkpXVCIsICJhbGciOiAiRWREU0EiIH0.eyAiaXNzIjogInI6MEQyN18yMjQ3RjdBMl9GNTZDMyIsICJzdWIiOiAiNzY1NjExOTk0ODE0NzY4ODciLCAiYXVkIjogWyAiY2xpZW50IiwgIndlYiIgXSwgImV4cCI6IDE2Nzk5MTkxNTMsICJuYmYiOiAxNjcxMTkyNTQyLCAiaWF0IjogMTY3OTgzMjU0MiwgImp0aSI6ICIwRDJEXzIyNDdGNzE0XzY1MjcwIiwgIm9hdCI6IDE2Nzk4MzI1NDAsICJydF9leHAiOiAxNjk3ODc4MzYyLCAicGVyIjogMCwgImlwX3N1YmplY3QiOiAiMTA0LjIyMy4xNTcuMjQ0IiwgImlwX2NvbmZpcm1lciI6ICIxMDQuMjIzLjE1Ny4yNDQiIH0.iOXQqpqwlHA1Z8lYlTGsdPpW_S1EYHX4rbBXTv6OVFyd-bg9KmIJCcmM6bIT2zyd13gcgAqSIV69jQ8J6nzFDw'
]

async function main() {
  let d = getSpoofedHostname()

  let body = {
    wallet_code: '4FHXX-736JH-D74PF',
    sessionid: randomBytes(12).toString('hex')
  }
  let session = new LoginSession(EAuthTokenPlatformType.WebBrowser, {httpProxy: 'http://fncuxkfd:niaxc2h1pwm7@104.223.157.244:6483'});

  // session.refreshToken = 'eyAidHlwIjogIkpXVCIsICJhbGciOiAiRWREU0EiIH0.eyAiaXNzIjogInN0ZWFtIiwgInN1YiI6ICI3NjU2MTE5OTQ4MTQ3Njg4NyIsICJhdWQiOiBbICJ3ZWIiLCAicmVuZXciLCAiZGVyaXZlIiBdLCAiZXhwIjogMTY5ODQwMzgwMywgIm5iZiI6IDE2NzEyNzU5ODksICJpYXQiOiAxNjc5OTE1OTg5LCAianRpIjogIjBEMkFfMjI0N0Y3QkVfQjEwNTciLCAib2F0IjogMTY3OTkxNTk4OSwgInBlciI6IDEsICJpcF9zdWJqZWN0IjogIjIwMy45MS44NS4xMTEiLCAiaXBfY29uZmlybWVyIjogIjIwMy45MS44NS4xMTEiIH0.2fucweOk403ans3YnY5yzIEDf0k8s7wkAJETenGvKx2EgDwitaH7y8FnAi7qIqHJZz6jnWK0VtCuZYkCPIERAw'
  session.refreshToken ='eyAidHlwIjogIkpXVCIsICJhbGciOiAiRWREU0EiIH0.eyAiaXNzIjogInN0ZWFtIiwgInN1YiI6ICI3NjU2MTE5OTQ0NjQ5MzI1MSIsICJhdWQiOiBbICJ3ZWIiLCAicmVuZXciLCAiZGVyaXZlIiBdLCAiZXhwIjogMTY5ODg2NTEwNiwgIm5iZiI6IDE2NzE5Njg0ODQsICJpYXQiOiAxNjgwNjA4NDg0LCAianRpIjogIjE3NDJfMjI1MEYxNENfODRGMzYiLCAib2F0IjogMTY4MDYwODQ4NCwgInBlciI6IDEsICJpcF9zdWJqZWN0IjogIjE4Ni4xNzkuMjMuMTc4IiwgImlwX2NvbmZpcm1lciI6ICIxMDQuMjIzLjE3MS4yMzciIH0.-pVLjr2hUliuo3L-pyp4kJJV3x1dOjOqY6Wn38Giqc0hw4lEd-eQA4r4j7RC2c_HAXxhB0TUdyNZD5eIYG8sBw'
  webCookies = await session.getWebCookies()

  let {headers} = getDataForPlatformType(session._platformType);
  // let headers = {
  //   'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36',
  //   origin: 'https://store.steampowered.com',
  //   referer: 'https://store.steampowered.com',
  //   cookie:''
  // }
  headers.cookie = webCookies.join(';')

  let finalizeResponse = await session._webClient.postEncoded('https://store.steampowered.com/account/ajaxredeemwalletcode/', body, 'multipart', {
    headers: headers
  });

  console.log(finalizeResponse.body)

}

main();

