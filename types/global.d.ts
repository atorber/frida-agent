/**
 * 全局类型声明文件
 * 用于 Frida Agent 环境的全局对象类型定义
 * 
 * 注意：Frida 相关的类型定义由 @types/frida-gum 提供
 * 此文件仅提供 console 等基础全局对象的声明
 */

/// <reference types="frida-gum" />

// 确保 console 可用（如果 @types/node 未安装）
// 如果 @types/node 已安装，这个声明会被覆盖，不会冲突
declare var console: {
    log(...args: any[]): void;
    error(...args: any[]): void;
    warn(...args: any[]): void;
    info(...args: any[]): void;
    debug(...args: any[]): void;
};

// 确保 global 对象可用
declare var global: typeof globalThis;

// 确保 URL 和 fetch 可用（用于 HTTP 请求）
declare var URL: {
    new(input: string, base?: string): URL;
    prototype: URL;
};
declare var fetch: (input: string | URL, init?: any) => Promise<any>;
declare var AbortController: {
    new(): AbortController;
    prototype: AbortController;
};

// 不再重复声明 Frida 全局对象，因为它们由 @types/frida-gum 提供
// 这样可以避免类型定义冲突

export {};
