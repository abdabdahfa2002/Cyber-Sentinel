

export type KillChainPhase =
  | 'Reconnaissance'
  | 'Weaponization'
  | 'Delivery'
  | 'Exploitation'
  | 'Installation'
  | 'Command and Control'
  | 'Actions on Objectives'
  | 'Uncategorized';

export type ArtifactType = 'AI_ANALYSIS' | 'ANALYST_NOTE' | 'TOOL_INFO' | 'TOOL_OUTPUT' | 'EVIDENCE_FILE' | 'CASE_INDEX' | 'GLOBAL_SUMMARY' | 'GLOBAL_IOC_LIST';

// Union type for all possible content structures within an artifact
export type ArtifactContent =
  | AnalysisResult
  | { text: string } // For ANALYST_NOTE, CASE_INDEX, and GLOBAL_SUMMARY
  | { toolName: string; version?: string; configuration?: string; } // For TOOL_INFO
  | { toolName: string; command?: string; output: string } // For TOOL_OUTPUT
  | { fileName: string; fileType: string; content: string } // For EVIDENCE_FILE
  | { iocsByPhase: Partial<Record<KillChainPhase, IndicatorOfCompromise[]>> } // For GLOBAL_IOC_LIST

export interface InvestigationArtifact {
  id: string;
  type: ArtifactType;
  title: string;
  content: ArtifactContent;
  createdAt: string;
  killChainPhase: KillChainPhase;
}

export interface ChatMessage {
  id: string;
  sender: 'user' | 'ai';
  text: string;
  timestamp: string;
}

export interface Case {
  id: string;
  name: string;
  description: string;
  status: 'New' | 'In Progress' | 'Closed';
  createdAt: string;
  artifacts: InvestigationArtifact[];
  investigationChecklist: ChecklistItem[];
  chatHistory: ChatMessage[];
}

// For the new comprehensive case creation modal
export interface NewCaseDetails {
  name: string;
  description: string;
  summary?: string;
  notes?: string;
  toolName?: string;
  toolVersion?: string;
  toolConfig?: string;
}


// --- AI Analysis Types ---
export interface MitreAttack {
  id: string;
  name: string;
  description: string;
}

export type IocType = 'IP Address' | 'File Hash' | 'Domain' | 'URL' | 'Email' | 'Other';

export interface IndicatorOfCompromise {
  type: IocType;
  value: string;
}

export interface ChecklistItem {
  step: number;
  action: string;
  details: string;
  completed: boolean; 
}

export interface TimelineEvent {
  timestamp: string;
  event: string;
}

export interface AnalysisResult {
  summary: string;
  estimated_severity: 'Low' | 'Medium' | 'High' | 'Critical' | 'Informational';
  attack_tactic: MitreAttack;
  attack_technique: MitreAttack;
  indicators_of_compromise: IndicatorOfCompromise[];
  investigation_checklist: Omit<ChecklistItem, 'completed'>[];
  timeline_events: TimelineEvent[];
}


// --- VirusTotal Base Types ---
export interface VTAnalysisStats {
  harmless: number;
  malicious: number;
  suspicious: number;
  undetected: number;
  timeout: number;
}

export interface VTOwner {
    asn?: number;
    as_owner?: string;
    country?: string;
}

export interface VTPcapIdpsRule {
    alert_severity: string;
    alert_context: string[];
    rule_msg: string;
    rule_sid: string;
    rule_gid: string;
    rule_category: string;
}

export interface VTPcapInfo {
    ids_rules?: VTPcapIdpsRule[];
    http_requests?: any[];
    dns_lookups?: any[];
}


// --- VirusTotal Report Types ---
export interface VTDomainReport {
  type: 'domain';
  id: string; // The domain name
  attributes: {
    last_analysis_stats: VTAnalysisStats;
    reputation: number;
    last_analysis_date?: number; // timestamp
    registrar?: string;
    creation_date?: number; // timestamp
    whois: string;
    categories?: Record<string, string>;
  };
  error?: string; 
}

export interface VTFileReport {
  type: 'file';
  id: string; // The hash
  attributes: {
    last_analysis_stats: VTAnalysisStats;
    meaningful_name?: string;
    names?: string[];
    size: number;
    type_description?: string;
    magic?: string;
    last_analysis_date?: number; // timestamp
    creation_date?: number; // timestamp
    signature_info?: { description: string; verified: string; };
    pcap_info?: VTPcapInfo;
  };
  error?: string;
}

export interface VTIPAddressReport {
    type: 'ip_address';
    id: string; // The IP address
    attributes: {
        last_analysis_stats: VTAnalysisStats;
        reputation: number;
        network: string;
        last_analysis_date?: number; // timestamp
        regional_internet_registry?: string;
        whois: string;
    } & VTOwner;
    error?: string;
}

export interface VTURLReport {
    type: 'url';
    id: string; // The URL identifier
    attributes: {
        last_analysis_stats: VTAnalysisStats;
        url: string;
        title?: string;
        reputation: number;
        last_analysis_date?: number;
        last_final_url?: string;
        last_http_response_code?: number;
        categories?: Record<string, string>;
    };
    error?: string;
}


export type VTReport = VTDomainReport | VTFileReport | VTIPAddressReport | VTURLReport;


// --- VirusTotal Relationship Types ---
// These are simplified versions of the full reports, used when they appear in relationships.
export interface VTDomain {
    id: string;
    type: 'domain';
    attributes: { last_analysis_stats: VTAnalysisStats; reputation: number; };
}

export interface VTFile {
  id: string; // SHA-256 hash
  type: 'file';
  attributes: {
    last_analysis_stats: VTAnalysisStats;
    last_analysis_date: number;
    meaningful_name?: string;
    names?: string[];
  };
}

export interface VTIPAddress {
    id: string;
    type: 'ip_address';
    attributes: { last_analysis_stats: VTAnalysisStats; reputation: number; };
}

export interface VTResolution {
  id: string; // Composite key
  type: 'resolution';
  attributes: {
    date: number; // timestamp
    ip_address: string;
    host_name: string;
  };
}

// Union type for any kind of relationship object VirusTotal might return.
export type VTRelationship = VTFile | VTResolution | VTDomain | VTIPAddress;

// --- User Agent Analysis Types ---
export interface UserAgentSecurityAnalysis {
  summary: string;
  risk_level: 'Informational' | 'Low' | 'Medium' | 'High' | 'Critical';
}

export interface UserAgentAnalysisResult {
  userAgentString: string;
  parsed: any | null;
  security: UserAgentSecurityAnalysis | null;
  parseError?: string;
  securityError?: string;
}