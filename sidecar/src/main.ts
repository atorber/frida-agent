/**
 *   Sidecar - https://github.com/huan/sidecar
 *
 *   @copyright 2021 Huan LI (李卓桓) <https://github.com/huan>
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *
 */
import {
  attach,
  detach,
}           from 'sidecar'

import { WeChatSidecar } from './wechat-sidecar'

async function main () {
  console.log('WeChat Sidecar starting...')

  const sidecar = new WeChatSidecar()
  await attach(sidecar)

  console.log('WeChat Sidecar started.')

  sidecar.on('hook', async args => {
    if (args instanceof Error) {
      console.error(args)
      return
    }
    console.log('recvMsg args:', args)
    const talkerId  = args.args['contactId'] as string
    const text      = args.args['text'] as string

    /**
     * The world's famous ding-dong bot.
     */
    if (talkerId && text === 'ding') {
      await sidecar.messageSendText(talkerId, 'dong')
      // talkerId, 'dong'
    }

  })

  const clean = () => detach(sidecar)

  process.on('SIGINT',  clean)
  process.on('SIGTERM', clean)
}

main()
  .catch(console.error)
