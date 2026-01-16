// frida-net.d.ts
declare module '@frida/net' {
  export function createServer(callback?: (socket: any) => void): any;
  export function connect(options: any, callback?: () => void): any;
  export function createConnection(options: any, callback?: () => void): any;
}