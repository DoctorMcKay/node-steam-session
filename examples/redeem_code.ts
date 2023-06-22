import {randomBytes} from "crypto";
import {EAuthTokenPlatformType, LoginSession} from "../src";
import {getDataForPlatformType, getSpoofedHostname} from "../src/helpers";

let webCookies = [
  'steamCountry=US%7Ce3a429901b56974b144d3b420e1973d0',
  'steamLoginSecure=76561199481476887%7C%7CeyAidHlwIjogIkpXVCIsICJhbGciOiAiRWREU0EiIH0.eyAiaXNzIjogInI6MEQyN18yMjQ3RjdBMl9GNTZDMyIsICJzdWIiOiAiNzY1NjExOTk0ODE0NzY4ODciLCAiYXVkIjogWyAiY2xpZW50IiwgIndlYiIgXSwgImV4cCI6IDE2Nzk5MTkxNTMsICJuYmYiOiAxNjcxMTkyNTQyLCAiaWF0IjogMTY3OTgzMjU0MiwgImp0aSI6ICIwRDJEXzIyNDdGNzE0XzY1MjcwIiwgIm9hdCI6IDE2Nzk4MzI1NDAsICJydF9leHAiOiAxNjk3ODc4MzYyLCAicGVyIjogMCwgImlwX3N1YmplY3QiOiAiMTA0LjIyMy4xNTcuMjQ0IiwgImlwX2NvbmZpcm1lciI6ICIxMDQuMjIzLjE1Ny4yNDQiIH0.iOXQqpqwlHA1Z8lYlTGsdPpW_S1EYHX4rbBXTv6OVFyd-bg9KmIJCcmM6bIT2zyd13gcgAqSIV69jQ8J6nzFDw'
]

async function main() {
  // let d = getSpoofedHostname()

  let body = {
    wallet_code: '4FHXX-736JH-D74PF',
    sessionid: randomBytes(12).toString('hex')
  }
  let session = new LoginSession(EAuthTokenPlatformType.SteamClient, {httpProxy: 'http://bmbxcqqo:9gfg86g3mmf0@38.153.147.14:6774'});

  // session.refreshToken = 'eyAidHlwIjogIkpXVCIsICJhbGciOiAiRWREU0EiIH0.eyAiaXNzIjogInN0ZWFtIiwgInN1YiI6ICI3NjU2MTE5OTQ4MTQ3Njg4NyIsICJhdWQiOiBbICJ3ZWIiLCAicmVuZXciLCAiZGVyaXZlIiBdLCAiZXhwIjogMTY5ODQwMzgwMywgIm5iZiI6IDE2NzEyNzU5ODksICJpYXQiOiAxNjc5OTE1OTg5LCAianRpIjogIjBEMkFfMjI0N0Y3QkVfQjEwNTciLCAib2F0IjogMTY3OTkxNTk4OSwgInBlciI6IDEsICJpcF9zdWJqZWN0IjogIjIwMy45MS44NS4xMTEiLCAiaXBfY29uZmlybWVyIjogIjIwMy45MS44NS4xMTEiIH0.2fucweOk403ans3YnY5yzIEDf0k8s7wkAJETenGvKx2EgDwitaH7y8FnAi7qIqHJZz6jnWK0VtCuZYkCPIERAw'
  session.refreshToken = 'eyAidHlwIjogIkpXVCIsICJhbGciOiAiRWREU0EiIH0.eyAiaXNzIjogInN0ZWFtIiwgInN1YiI6ICI3NjU2MTE5OTQ4MDU4OTE5MyIsICJhdWQiOiBbICJjbGllbnQiLCAid2ViIiwgInJlbmV3IiwgImRlcml2ZSIgXSwgImV4cCI6IDE3MDU4MDE2ODcsICJuYmYiOiAxNjc4Nzg4NDU5LCAiaWF0IjogMTY4NzQyODQ1OSwgImp0aSI6ICIwRDE4XzIyQkJDQUQxX0ZEMEM5IiwgIm9hdCI6IDE2ODc0Mjg0NTksICJwZXIiOiAxLCAiaXBfc3ViamVjdCI6ICIzOC4xNTMuMTQ3LjE0IiwgImlwX2NvbmZpcm1lciI6ICIzOC4xNTMuMTQ3LjE0IiB9.TTSp49gpOFg5laGtM1AjbW_UOrOlL3Kjh-iHPkatAJF_1pb48nhZ6nQPKJGTheSAe4NRndYOGLliCrz_F67CBQ'
  // session.refreshToken = 'eyAidHlwIjogIkpXVCIsICJhbGciOiAiRWREU0EiIH0.eyAiaXNzIjogInI6MEQxOF8yMkJCQ0FEMV9GRDBDOSIsICJzdWIiOiAiNzY1NjExOTk0ODA1ODkxOTMiLCAiYXVkIjogWyAiY2xpZW50IiwgIndlYiIgXSwgImV4cCI6IDE2ODc1MTY2ODIsICJuYmYiOiAxNjc4Nzg4NTE3LCAiaWF0IjogMTY4NzQyODUxNywgImp0aSI6ICIwRDBFXzIyQkJDQUNBX0U5RTk3IiwgIm9hdCI6IDE2ODc0Mjg0NTksICJydF9leHAiOiAxNzA1ODAxNjg3LCAicGVyIjogMCwgImlwX3N1YmplY3QiOiAiMzguMTUzLjE0Ny4xNCIsICJpcF9jb25maXJtZXIiOiAiMzguMTUzLjE0Ny4xNCIgfQ.zmHgCvSmnGphhW8DTjTEFMxKBgfRiDAcuJbhNZIZXws3dZpkYGszr5ShmtBzbBa0dFJxhXk2u3xMq8tY8ftEDg'
  await session.refreshAccessToken();
  console.log(`New access token: ${session.accessToken}`);
  webCookies = await session.getWebCookies()
  console.log('webCookies',webCookies)
  // @ts-ignore
  let {headers} = getDataForPlatformType(session._platformType);
  // let headers = {
  //   'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36',
  //   origin: 'https://store.steampowered.com',
  //   referer: 'https://store.steampowered.com',
  //   cookie:''
  // }
  headers.cookie = webCookies.join(';')
  // @ts-ignore
  let finalizeResponse = await session._webClient.request({
    url: 'https://store.steampowered.com/account/ajaxredeemwalletcode/',
    json: body,
    headers: headers
  });

  console.log(finalizeResponse.jsonBody)

}

main();

