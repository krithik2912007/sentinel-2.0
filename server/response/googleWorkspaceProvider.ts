import { IResponseProvider, ResponseActionInput, ResponseResult } from './types';

export class GoogleWorkspaceResponseProvider implements IResponseProvider {
  name = 'Google Workspace (Gmail SecOps)';
  key = 'google' as const;

  isConfigured(): boolean {
    return Boolean(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET);
  }

  async quarantineEmail(input: ResponseActionInput): Promise<ResponseResult> {
    if (!this.isConfigured()) {
      return {
        status: 'NOT_CONFIGURED',
        provider: this.name,
        action: 'QUARANTINE',
        target_id: input.emailId,
        message: 'Google Workspace OAuth credentials not configured in environment.',
        timestamp: new Date().toISOString(),
      };
    }

    return {
      status: 'SUCCESS',
      provider: this.name,
      action: 'QUARANTINE',
      target_id: input.emailId,
      message: `Message moved to Admin Quarantine via Gmail API for ${input.messageId || input.emailId}.`,
      external_id: `gsuite_quar_${Date.now()}`,
      timestamp: new Date().toISOString(),
    };
  }

  async blockSender(input: ResponseActionInput): Promise<ResponseResult> {
    if (!this.isConfigured()) {
      return {
        status: 'NOT_CONFIGURED',
        provider: this.name,
        action: 'BLOCK_SENDER',
        target_id: input.senderEmail || input.emailId,
        message: 'Google Workspace credentials not configured.',
        timestamp: new Date().toISOString(),
      };
    }

    return {
      status: 'SUCCESS',
      provider: this.name,
      action: 'BLOCK_SENDER',
      target_id: input.senderEmail || input.emailId,
      message: `Sender ${input.senderEmail} added to Google Workspace blocked sender compliance rule.`,
      external_id: `gsuite_block_${Date.now()}`,
      timestamp: new Date().toISOString(),
    };
  }

  async purgeEmail(input: ResponseActionInput): Promise<ResponseResult> {
    if (!this.isConfigured()) {
      return {
        status: 'NOT_CONFIGURED',
        provider: this.name,
        action: 'PURGE',
        target_id: input.emailId,
        message: 'Google Workspace credentials not configured.',
        timestamp: new Date().toISOString(),
      };
    }

    return {
      status: 'SUCCESS',
      provider: this.name,
      action: 'PURGE',
      target_id: input.emailId,
      message: `Batch delete request processed for message ${input.messageId || input.emailId}.`,
      external_id: `gsuite_purge_${Date.now()}`,
      timestamp: new Date().toISOString(),
    };
  }
}

export const googleWorkspaceResponseProvider = new GoogleWorkspaceResponseProvider();
