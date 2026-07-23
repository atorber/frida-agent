import { FinderFeedInfo, FinderFeedMedia, ParsedAppMsg } from './types.js'

function decodeXmlEntities(s: string): string {
    return s
        .replace(/&amp;/g, '&')
        .replace(/&lt;/g, '<')
        .replace(/&gt;/g, '>')
        .replace(/&quot;/g, '"')
        .replace(/&apos;/g, "'")
}

function extractTag(xml: string, tag: string): string {
    const match = xml.match(new RegExp(`<${tag}>([^<]*)</${tag}>`))
    if (match) {
        return decodeXmlEntities(match[1].trim())
    }
    if (xml.match(new RegExp(`<${tag}\\s*/>`))) {
        return ''
    }
    return ''
}

function extractBlock(xml: string, tag: string): string {
    const match = xml.match(new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`))
    return match ? match[1] : ''
}

function parseFinderFeedMedia(mediaXml: string): FinderFeedMedia {
    return {
        mediaType: Number(extractTag(mediaXml, 'mediaType')) || 0,
        url: extractTag(mediaXml, 'url'),
        coverUrl: extractTag(mediaXml, 'coverUrl'),
        thumbUrl: extractTag(mediaXml, 'thumbUrl'),
        width: Number(extractTag(mediaXml, 'width')) || 0,
        height: Number(extractTag(mediaXml, 'height')) || 0,
        videoPlayDuration: Number(extractTag(mediaXml, 'videoPlayDuration')) || 0,
    }
}

function parseFinderFeed(finderFeedXml: string): FinderFeedInfo {
    const mediaListXml = extractBlock(finderFeedXml, 'mediaList')
    const mediaBlocks = mediaListXml.match(/<media>([\s\S]*?)<\/media>/g) || []
    const mediaList = mediaBlocks.map(block => parseFinderFeedMedia(block))

    return {
        objectId: extractTag(finderFeedXml, 'objectId'),
        feedType: Number(extractTag(finderFeedXml, 'feedType')) || 0,
        nickname: extractTag(finderFeedXml, 'nickname'),
        avatar: extractTag(finderFeedXml, 'avatar'),
        desc: extractTag(finderFeedXml, 'desc'),
        mediaCount: Number(extractTag(finderFeedXml, 'mediaCount')) || 0,
        objectNonceId: extractTag(finderFeedXml, 'objectNonceId'),
        username: extractTag(finderFeedXml, 'username'),
        mediaList,
    }
}

export function parseAppMsg(xml: string): ParsedAppMsg | null {
    if (!xml || !xml.includes('<appmsg')) {
        return null
    }

    const appmsgXml = extractBlock(xml, 'appmsg') || xml
    const subType = Number(extractTag(appmsgXml, 'type')) || 0

    const result: ParsedAppMsg = {
        subType,
        title: extractTag(appmsgXml, 'title'),
        des: extractTag(appmsgXml, 'des'),
        url: extractTag(appmsgXml, 'url'),
    }

    if (subType === 51) {
        const finderFeedXml = extractBlock(appmsgXml, 'finderFeed')
        if (finderFeedXml) {
            result.finderFeed = parseFinderFeed(finderFeedXml)
        }
    }

    return result
}

export function getFileNameFromAppMsg(xml: string, selfId: string): string | null {
    const parsed = parseAppMsg(xml)
    if (!parsed || parsed.subType !== 6 || !parsed.title) {
        return null
    }

    const curTime = new Date()
    const month = curTime.getMonth() + 1
    const monthStr = curTime.getMonth() < 9 ? `0${month}` : `${month}`
    return `${selfId}\\FileStorage\\File\\${curTime.getFullYear()}-${monthStr}\\${parsed.title}`
}
