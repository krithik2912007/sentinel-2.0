export type ResponseActionStatus = 'SUCCESS' | 'SIMULATED' | 'NOT_CONFIGURED' | 'ERROR';

export interface ResponseResult {
  status: ResponseActionStatus;
  provider: string;
  provider_key?: 'm365' | 'google' | 'simulation';
  action: 'QUARANTINE' | 'BLOCK_SENDER' | 'PURGE';
  target_id: string;
  message: string;
  external_id?: string;
  timestamp: string;
}

export interface ResponseActionInput {
  emailId: string;
  senderEmail?: string;
  subject?: string;
  messageId?: string;
  reason?: string;
  actorId: string;
  actorEmail: string;
  actorRole: string;
  ipAddress?: string;
  preferredProvider?: 'm365' | 'google' | 'simulation' | 'auto';
  simulationMode?: boolean;
}

export interface IResponseProvider {
  name: string;
  key: 'm365' | 'google' | 'simulation';
  isConfigured(): boolean;
  quarantineEmail(input: ResponseActionInput): Promise<ResponseResult>;
  blockSender(input: ResponseActionInput): Promise<ResponseResult>;
  purgeEmail(input: ResponseActionInput): Promise<ResponseResult>;
}

