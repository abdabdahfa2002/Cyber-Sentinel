


import React, { useState, useEffect } from 'react';
import { getRelationship } from '../services/virusTotalService';
import type { VTFileReport, VTDomain, VTIPAddress, VTRelationship } from '../types';
import { XCircleIcon, InfoIcon, GlobeAltIcon, ServerIcon, ShareIcon, ShieldExclamationIcon } from './icons';
import { useLocalization } from '../contexts/LocalizationContext';

type DetailTab = 'summary' | 'domains' | 'ips' | 'pcap';

interface VTFileDetailsProps {
  fileReport: VTFileReport;
  apiKey: string;
  onClose: () => void;
}

const LoadingSpinner: React.FC = () => {
    const { t } = useLocalization();
    return (
        <div className="flex items-center justify-center space-x-2">
            <div className="w-4 h-4 border-2 border-dashed rounded-full animate-spin border-sentinel-blue"></div>
            <span className="text-gray-400">{t('loading')}...</span>
        </div>
    );
}

const DetailCard: React.FC<{ title: string, children: React.ReactNode, Icon: React.FC<{className?: string;}> }> = ({ title, Icon, children }) => (
    <div className="bg-sentinel-gray-dark border border-sentinel-gray-light rounded-lg p-4">
        <h3 className="text-lg font-semibold text-gray-200 flex items-center mb-3">
            <Icon className="h-5 w-5 mr-2 text-sentinel-blue" />
            {title}
        </h3>
        {children}
    </div>
);

const ErrorDisplay: React.FC<{ message: string }> = ({ message }) => (
    <p className="text-sm text-yellow-300 p-3 bg-yellow-900/50 rounded-md border border-yellow-700">{message}</p>
);

const VTFileDetails: React.FC<VTFileDetailsProps> = ({ fileReport, apiKey, onClose }) => {
    const { t } = useLocalization();
    const [activeTab, setActiveTab] = useState<DetailTab>('summary');
    const [isLoading, setIsLoading] = useState<boolean>(false);
    const [contactedDomains, setContactedDomains] = useState<VTDomain[]>([]);
    const [contactedIPs, setContactedIPs] = useState<VTIPAddress[]>([]);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        const fetchRelationships = async () => {
            if (activeTab === 'summary' || activeTab === 'pcap') {
                setIsLoading(false);
                return;
            };
            
            setIsLoading(true);
            setError(null);
            
            try {
                let relationshipData: VTRelationship[] = [];
                if (activeTab === 'domains') {
                    relationshipData = await getRelationship(apiKey, 'files', fileReport.id, 'contacted_domains');
                    setContactedDomains(relationshipData as VTDomain[]);
                } else if (activeTab === 'ips') {
                    relationshipData = await getRelationship(apiKey, 'files', fileReport.id, 'contacted_ips');
                    setContactedIPs(relationshipData as VTIPAddress[]);
                }
            } catch (err) {
                setError(err instanceof Error ? err.message : 'An unknown error occurred.');
            } finally {
                setIsLoading(false);
            }
        };
        fetchRelationships();
    }, [activeTab, apiKey, fileReport.id]);

    const renderSummary = () => {
        const { attributes } = fileReport;
        return (
            <div className="space-y-4">
                <DetailCard title="File Properties" Icon={InfoIcon}>
                    <div className="grid grid-cols-2 gap-4 text-sm">
                        <div><strong className="text-gray-400">Main Name:</strong> <span className="text-cyan-300">{attributes.meaningful_name || 'N/A'}</span></div>
                        <div><strong className="text-gray-400">Size:</strong> {attributes.size ? `${(attributes.size / 1024).toFixed(2)} KB` : 'N/A'}</div>
                        <div><strong className="text-gray-400">Type:</strong> {attributes.type_description || 'N/A'}</div>
                        <div><strong className="text-gray-400">Magic String:</strong> {attributes.magic || 'N/A'}</div>
                        <div className="col-span-2"><strong className="text-gray-400">Signature:</strong> {attributes.signature_info?.description || 'N/A'}</div>
                    </div>
                </DetailCard>
                 <DetailCard title="Other Known Names" Icon={InfoIcon}>
                    {attributes.names && attributes.names.length > 0 ? (
                        <div className="flex flex-wrap gap-2 max-h-40 overflow-y-auto">
                            {attributes.names.map((name, i) => (
                                <code key={i} className="px-2 py-1 text-xs bg-sentinel-gray-light text-gray-300 rounded-md">{name}</code>
                            ))}
                        </div>
                    ) : <p className="text-sm text-gray-400">No other names recorded.</p>}
                </DetailCard>
            </div>
        );
    };

     const renderPcapAnalysis = () => {
        const pcapInfo = fileReport.attributes.pcap_info;
        if (!pcapInfo?.ids_rules || pcapInfo.ids_rules.length === 0) {
            return <p className="text-sm text-gray-400">No IDS rule matches found in the PCAP file.</p>;
        }
        return (
            <div className="overflow-x-auto max-h-80">
                <table className="w-full text-sm text-left">
                    <thead className="text-xs text-gray-400 uppercase bg-sentinel-gray-light sticky top-0">
                        <tr>
                            <th className="px-4 py-2">Severity</th>
                            <th className="px-4 py-2">Rule Message</th>
                            <th className="px-4 py-2">Category</th>
                            <th className="px-4 py-2">SID</th>
                        </tr>
                    </thead>
                    <tbody className="text-gray-300">
                        {pcapInfo.ids_rules.map((rule, index) => (
                            <tr key={`${rule.rule_sid}-${index}`} className="border-b border-sentinel-gray-light hover:bg-sentinel-gray-light/50">
                                <td className="px-4 py-2 capitalize">{rule.alert_severity}</td>
                                <td className="px-4 py-2">{rule.rule_msg}</td>
                                <td className="px-4 py-2">{rule.rule_category}</td>
                                <td className="px-4 py-2 font-mono">{rule.rule_sid}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        );
    };

    const renderTable = (data: (VTDomain | VTIPAddress)[], type: 'domain' | 'ip') => (
        <div className="overflow-x-auto max-h-80">
            <table className="w-full text-sm text-left">
                <thead className="text-xs text-gray-400 uppercase bg-sentinel-gray-light sticky top-0">
                    <tr>
                        <th className="px-4 py-2">{type === 'domain' ? 'Domain' : 'IP Address'}</th>
                        <th className="px-4 py-2 text-center">Detections</th>
                        <th className="px-4 py-2 text-center">Reputation</th>
                    </tr>
                </thead>
                <tbody className="text-gray-300">
                    {data.map(item => (
                        <tr key={item.id} className="border-b border-sentinel-gray-light hover:bg-sentinel-gray-light/50">
                            <td className="px-4 py-2 font-mono text-xs break-all">{item.id}</td>
                            <td className="px-4 py-2 text-center text-red-400 font-semibold">{item.attributes.last_analysis_stats.malicious}</td>
                            <td className="px-4 py-2 text-center">{item.attributes.reputation}</td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );

    const renderContent = () => {
        if (isLoading) return <LoadingSpinner />;
        if (error) return <ErrorDisplay message={error} />;

        switch (activeTab) {
            case 'summary': return renderSummary();
            case 'domains':
                return contactedDomains.length > 0 ? renderTable(contactedDomains, 'domain') : <p className="text-sm text-gray-400">No contacted domains found.</p>;
            case 'ips':
                return contactedIPs.length > 0 ? renderTable(contactedIPs, 'ip') : <p className="text-sm text-gray-400">No contacted IPs found.</p>;
            case 'pcap':
                return renderPcapAnalysis();
            default: return null;
        }
    };

    const getTabTitle = (tab: DetailTab) => {
        switch (tab) {
            case 'summary': return t('summary');
            case 'domains': return t('contactedDomains');
            case 'ips': return t('contactedIPs');
            case 'pcap': return t('pcapAnalysis');
            default: return '';
        }
    };
    
    const getContentTitle = () => {
        switch (activeTab) {
            case 'summary': return "File Properties";
            case 'pcap': return t('idsRules');
            default: return "Relationships";
        }
    }
    
    const getIcon = () => {
        switch (activeTab) {
            case 'summary': return InfoIcon;
            case 'pcap': return ShieldExclamationIcon;
            default: return ShareIcon;
        }
    }


    return (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50 animate-fade-in" onClick={onClose}>
            <div className="bg-sentinel-gray-medium w-full max-w-4xl h-full max-h-[90vh] rounded-xl shadow-2xl border border-sentinel-gray-light flex flex-col" onClick={e => e.stopPropagation()}>
                <div className="flex items-center justify-between p-4 border-b border-sentinel-gray-light">
                    <div>
                        <h2 className="text-xl font-bold text-gray-100">File Hash Analysis</h2>
                        <p className="text-sm font-mono text-cyan-300 break-all">{fileReport.id}</p>
                    </div>
                    <button onClick={onClose} className="text-gray-400 hover:text-white"><XCircleIcon className="h-8 w-8" /></button>
                </div>
                <div className="p-4 border-b border-sentinel-gray-light">
                    <div className="flex space-x-2 rounded-lg bg-sentinel-gray-dark p-1">
                        {(['summary', 'domains', 'ips'] as DetailTab[]).map(tab => (
                             <button key={tab} onClick={() => setActiveTab(tab)} className={`w-full rounded-md px-3 py-2 text-sm font-medium text-center transition-colors capitalize ${activeTab === tab ? 'bg-sentinel-blue text-white' : 'text-gray-400 hover:bg-sentinel-gray-light/50'}`}>{getTabTitle(tab)}</button>
                        ))}
                        {fileReport.attributes.pcap_info && (
                             <button onClick={() => setActiveTab('pcap')} className={`w-full rounded-md px-3 py-2 text-sm font-medium text-center transition-colors capitalize ${activeTab === 'pcap' ? 'bg-sentinel-blue text-white' : 'text-gray-400 hover:bg-sentinel-gray-light/50'}`}>{getTabTitle('pcap')}</button>
                        )}
                    </div>
                </div>
                <div className="p-6 overflow-y-auto">
                    <DetailCard title={getContentTitle()} Icon={getIcon()}>
                        {renderContent()}
                    </DetailCard>
                </div>
            </div>
            <style>{`
                @keyframes fade-in { from { opacity: 0; } to { opacity: 1; } }
                .animate-fade-in { animation: fade-in 0.2s ease-out forwards; }
            `}</style>
        </div>
    );
};

export default VTFileDetails;