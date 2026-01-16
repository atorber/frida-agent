// Type definitions for @frida namespace
declare module '@frida/net' {
  export function createServer(callback?: (socket: any) => void): any;
  export function connect(options: any, callback?: () => void): any;
  export function createConnection(options: any, callback?: () => void): any;
  export class Socket {
    on(event: string, callback: (...args: any[]) => void): void;
    write(data: any): void;
    end(): void;
    destroy(): void;
  }
  export class Server {
    listen(port: number, callback?: () => void): void;
    close(callback?: () => void): void;
  }
}
