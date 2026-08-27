import { auditRepository } from '../db/repositories/auditRepository';
import { simulationResponseProvider } from './simulationProvider';
import { m365ResponseProvider } from './m365Provider';
import { googleWorkspaceResponseProvider } from './googleWorkspaceProvider';
import { IResponseProvider, ResponseActionInput, ResponseResult } from './types';

export class ResponseManager {
  private resolveProvider(input?: ResponseActionInput): IResponseProvider {
    const isGlobalSimulation = process.env.SIMULATION_MODE !== 'false';

    // If explicit simulation flag is set on the request or global environment
    if (input?.simulationMode || (input?.preferredProvider === 'simulation')) {
      return simulationResponseProvider;
    }

    if (input?.preferredProvider === 'm365') {
      return m365ResponseProvider;
    }

    if (input?.preferredProvider === 'google') {
      return googleWorkspaceResponseProvider;
    }

    if (isGlobalSimulation) {
      return simulationResponseProvider;
    }

    if (m365ResponseProvider.isConfigured()) {
      return m365ResponseProvider;
    }

    if (googleWorkspaceResponseProvider.isConfigured()) {
      return googleWorkspaceResponseProvider;
    }

    // Default to simulation provider if no live tenant configured
    return simulationResponseProvider;
  }

  getRemediationProviders(): Array<{
    key: 'm365' | 'google' | 'simulation';
    name: string;
    configured: boolean;
    status: 'LIVE' | 'NOT_CONFIGURED' | 'SIMULATED';
    description: string;
    supported_actions: string[];
  }> {
    return [
      {
        key: 'm365',
        name: m365ResponseProvider.name,
        configured: m365ResponseProvider.isConfigured(),
        status: m365ResponseProvider.isConfigured() ? 'LIVE' : 'NOT_CONFIGURED',
        description: 'Microsoft Graph Security API & Exchange Online Protection Tenant Blocklist',
        supported_actions: ['QUARANTINE', 'BLOCK_SENDER', 'PURGE'],
      },
      {
        key: 'google',
        name: googleWorkspaceResponseProvider.name,
        configured: googleWorkspaceResponseProvider.isConfigured(),
        status: googleWorkspaceResponseProvider.isConfigured() ? 'LIVE' : 'NOT_CONFIGURED',
        description: 'Google Workspace Gmail SecOps Admin Quarantine & Routing Rules',
        supported_actions: ['QUARANTINE', 'BLOCK_SENDER', 'PURGE'],
      },
      {
        key: 'simulation',
        name: simulationResponseProvider.name,
        configured: true,
        status: 'SIMULATED',
        description: 'Deterministic SOC Isolation Sandbox (Safe for testing & training exercises)',
        supported_actions: ['QUARANTINE', 'BLOCK_SENDER', 'PURGE'],
      },
    ];
  }

  async quarantine(input: ResponseActionInput): Promise<ResponseResult> {
    const provider = this.resolveProvider(input);
    const result = await provider.quarantineEmail(input);
    result.provider_key = provider.key;

    await auditRepository.log({
      id: `audit_act_${Date.now()}`,
      timestamp: new Date().toISOString(),
      user_id: input.actorId,
      user_email: input.actorEmail,
      user_role: input.actorRole as any,
      action: 'EMAIL_QUARANTINE',
      target_type: 'EMAIL',
      target_id: input.emailId,
      details: `${result.status} | Provider: ${result.provider} | Reason: ${input.reason || 'Forensic threat score exceeded threshold'}`,
      ip_address: input.ipAddress || '127.0.0.1',
    });

    return result;
  }

  async blockSender(input: ResponseActionInput): Promise<ResponseResult> {
    const provider = this.resolveProvider(input);
    const result = await provider.blockSender(input);
    result.provider_key = provider.key;

    await auditRepository.log({
      id: `audit_act_${Date.now()}`,
      timestamp: new Date().toISOString(),
      user_id: input.actorId,
      user_email: input.actorEmail,
      user_role: input.actorRole as any,
      action: 'SENDER_BLOCK',
      target_type: 'DOMAIN_OR_SENDER',
      target_id: input.senderEmail || input.emailId,
      details: `${result.status} | Provider: ${result.provider} | Reason: ${input.reason || 'Malicious sender infrastructure'}`,
      ip_address: input.ipAddress || '127.0.0.1',
    });

    return result;
  }

  async purge(input: ResponseActionInput): Promise<ResponseResult> {
    const provider = this.resolveProvider(input);
    const result = await provider.purgeEmail(input);
    result.provider_key = provider.key;

    await auditRepository.log({
      id: `audit_act_${Date.now()}`,
      timestamp: new Date().toISOString(),
      user_id: input.actorId,
      user_email: input.actorEmail,
      user_role: input.actorRole as any,
      action: 'EMAIL_PURGE',
      target_type: 'EMAIL',
      target_id: input.emailId,
      details: `${result.status} | Provider: ${result.provider} | Reason: ${input.reason || 'Direct malicious payload delivery'}`,
      ip_address: input.ipAddress || '127.0.0.1',
    });

    return result;
  }
}

export const responseManager = new ResponseManager();

