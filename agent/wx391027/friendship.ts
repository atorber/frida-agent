/*
获取好友请求
*/
async function friendshipRawPayload(id: string): Promise<any> {
    return { id } as any
}

/*
手机号搜索好友
*/
async function friendshipSearchPhone(
    phone: string,
): Promise<null | string> {
    return null
}

/*
微信号搜索好友
*/
async function friendshipSearchWeixin(
    weixin: string,
): Promise<null | string> {
    return null
}

/*
发送好友请求
*/
async function friendshipAdd(
    contactId: string,
    hello: string,
): Promise<void> { }

/*
接受好友请求
*/
async function friendshipAccept(
    friendshipId: string,
): Promise<void> { }