import { IResponseProvider, ResponseActionInput, ResponseResult } from './types';

export class SimulationResponseProvider implements IResponseProvider {
  name = 'Simulation (SOC Sandbox)';
  key = 'simulation' as const;

  isConfigured(): boolean {
    return true;
  }

  async quarantineEmail(input: ResponseActionInput): Promise<ResponseResult> {
    return {
      status: 'SIMULATED',
      provider: this.name,
      action: 'QUARANTINE',
      target_id: input.emailId,
      message: `[SIMULATION] Email ${input.emailId} flagged for quarantine isolation. No live Microsoft 365 / Google Workspace tenant was modified.`,
      external_id: `sim_quarantine_${Date.now()}`,
      timestamp: new Date().toISOString(),
    };
  }

  async blockSender(input: ResponseActionInput): Promise<ResponseResult> {
    return {
      status: 'SIMULATED',
      provider: this.name,
      action: 'BLOCK_SENDER',
      target_id: input.senderEmail || input.emailId,
      message: `[SIMULATION] Sender domain/email '${input.senderEmail || 'N/A'}' added to simulated edge blocklist.`,
      external_id: `sim_block_${Date.now()}`,
      timestamp: new Date().toISOString(),
    };
  }

  async purgeEmail(input: ResponseActionInput): Promise<ResponseResult> {
    return {
      status: 'SIMULATED',
      provider: this.name,
      action: 'PURGE',
      target_id: input.emailId,
      message: `[SIMULATION] Hard-delete purge command recorded for message ID '${input.messageId || input.emailId}'.`,
      external_id: `sim_purge_${Date.now()}`,
      timestamp: new Date().toISOString(),
    };
  }
}

export const simulationResponseProvider = new SimulationResponseProvider();
