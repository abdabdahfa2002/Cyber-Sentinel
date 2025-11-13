

import React, { useState, useEffect } from 'react';
import { getRelationship } from '../services/virusTotalService';
import type { VTIPAddressReport, VTRelationship, VTFile, VTResolution } from '../types';
import { XCircleIcon, InfoIcon, DocumentDuplicateIcon, GlobeAltIcon, ShareIcon } from './icons';

type DetailTab = 'summary' | 'resolutions' | 'files';

interface VTIPDetailsProps {
  ipReport: VTIPAddressReport;
  apiKey: string;
  onClose: () => void;
}

const LoadingSpinner: React.FC = () => (
    <div className="flex items-center justify-center space-x-2">
        <div className="w-4 h-4 border-2 border-dashed rounded-full animate-spin border-sentinel-blue"></div>
        <span className="text-gray-400">Loading...</span>
    </div>
);

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

const VTIPDetails: React.FC<VTIPDetailsProps> = ({ ipReport, apiKey, onClose }) => {
    const [activeTab, setActiveTab] = useState<DetailTab>('summary');
    const [isLoading, setIsLoading] = useState<boolean>(false);
    const [resolutions, setResolutions] = useState<VTResolution[]>([]);
    const [relatedFiles, setRelatedFiles] = useState<VTFile[]>([]);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        const fetchRelationships = async () => {
            if (activeTab === 'summary') return;
            
            setIsLoading(true);
            setError(null);
            
            try {
                let relationshipData: VTRelationship[] = [];
                if (activeTab === 'resolutions') {
                    relationshipData = await getRelationship(apiKey, 'ip_addresses', ipReport.id, 'resolutions');
                    setResolutions(relationshipData as VTResolution[]);
                } else if (activeTab === 'files') {
                    const [communicating, downloaded] = await Promise.all([
                        getRelationship(apiKey, 'ip_addresses', ipReport.id, 'communicating_files'),
                        getRelationship(apiKey, 'ip_addresses', ipReport.id, 'downloaded_files'),
                    ]);
                    const allFiles = [...communicating as VTFile[], ...downloaded as VTFile[]];
                    const uniqueFiles = Array.from(new Map(allFiles.map(file => [file.id, file])).values());
                    setRelatedFiles(uniqueFiles);
                }
            } catch (err) {
                setError(err instanceof Error ? err.message : 'An unknown error occurred.');
            } finally {
                setIsLoading(false);
            }
        };
        fetchRelationships();
    }, [activeTab, apiKey, ipReport.id]);

    const renderSummary = () => {
        const { attributes } = ipReport;
        return (
            <DetailCard title="IP Properties" Icon={InfoIcon}>
                <div className="grid grid-cols-2 gap-4 text-sm">
                    <div><strong className="text-gray-400">Owner:</strong> <span className="text-cyan-300">{attributes.as_owner || 'N/A'}</span></div>
                    <div><strong className="text-gray-400">ASN:</strong> {attributes.asn || 'N/A'}</div>
                    <div><strong className="text-gray-400">Country:</strong> {attributes.country || 'N/A'}</div>
                    <div><strong className="text-gray-400">RIR:</strong> {attributes.regional_internet_registry || 'N/A'}</div>
                    <div className="col-span-2"><strong className="text-gray-400">Network:</strong> <span className="font-mono">{attributes.network || 'N/A'}</span></div>
                </div>
            </DetailCard>
        );
    };

    const renderTable = (data: (VTResolution | VTFile)[]) => (
        <div className="overflow-x-auto max-h-80">
            <table className="w-full text-sm text-left">
                <thead className="text-xs text-gray-400 uppercase bg-sentinel-gray-light sticky top-0">
                    <tr>
                    {activeTab === 'resolutions' ? (
                        <>
                            <th className="px-4 py-2">Hostname</th>
                            <th className="px-4 py-2">Last Seen</th>
                        </>
                    ) : (
                        <>
                            <th className="px-4 py-2">SHA-256</th>
                            <th className="px-4 py-2 text-center">Detections</th>
                            <th className="px-4 py-2">File Name</th>
                        </>
                    )}
                    </tr>
                </thead>
                <tbody className="text-gray-300">
                    {data.map(item => (
                        <tr key={item.id} className="border-b border-sentinel-gray-light hover:bg-sentinel-gray-light/50">
                            {item.type === 'resolution' ? (
                                <>
                                    <td className="px-4 py-2 font-mono text-xs break-all">{item.attributes.host_name}</td>
                                    <td className="px-4 py-2">{new Date(item.attributes.date * 1000).toLocaleString()}</td>
                                </>
                            ) : (
                                <>
                                    <td className="px-4 py-2 font-mono text-xs break-all">{item.id}</td>
                                    <td className="px-4 py-2 text-center text-red-400 font-semibold">{item.attributes.last_analysis_stats.malicious}</td>
                                    <td className="px-4 py-2 text-cyan-300 break-all">{item.attributes.meaningful_name || item.attributes.names?.[0] || 'N/A'}</td>
                                </>
                            )}
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
    

    const renderContent = () => {
        if (activeTab === 'summary') return renderSummary();
        if (isLoading) return <LoadingSpinner />;
        if (error) return <ErrorDisplay message={error} />;

        switch (activeTab) {
            case 'resolutions':
                return resolutions.length > 0 ? renderTable(resolutions) : <p className="text-sm text-gray-400">No domain resolutions found.</p>;
            case 'files':
                return relatedFiles.length > 0 ? renderTable(relatedFiles) : <p className="text-sm text-gray-400">No associated files found.</p>;
            default: return null;
        }
    };
    
    const ICONS: {[key in DetailTab]: React.FC<{className?: string}>} = {
        summary: InfoIcon,
        resolutions: GlobeAltIcon,
        files: DocumentDuplicateIcon,
    };
    const Title: {[key in DetailTab]: string} = {
        summary: "IP Properties",
        resolutions: "Domain Resolutions",
        files: "Associated Files",
    };

    return (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50 animate-fade-in" onClick={onClose}>
            <div className="bg-sentinel-gray-medium w-full max-w-4xl h-full max-h-[90vh] rounded-xl shadow-2xl border border-sentinel-gray-light flex flex-col" onClick={e => e.stopPropagation()}>
                <div className="flex items-center justify-between p-4 border-b border-sentinel-gray-light">
                    <div>
                        <h2 className="text-xl font-bold text-gray-100">IP Address Analysis</h2>
                        <p className="text-sm font-mono text-cyan-300">{ipReport.id}</p>
                    </div>
                    <button onClick={onClose} className="text-gray-400 hover:text-white"><XCircleIcon className="h-8 w-8" /></button>
                </div>
                <div className="p-4 border-b border-sentinel-gray-light">
                    <div className="flex space-x-2 rounded-lg bg-sentinel-gray-dark p-1">
                       {(['summary', 'resolutions', 'files'] as DetailTab[]).map(tab => (
                            <button key={tab} onClick={() => setActiveTab(tab)} className={`w-full rounded-md px-3 py-2 text-sm font-medium text-center transition-colors capitalize ${activeTab === tab ? 'bg-sentinel-blue text-white' : 'text-gray-400 hover:bg-sentinel-gray-light/50'}`}>{Title[tab]}</button>
                       ))}
                    </div>
                </div>
                <div className="p-6 overflow-y-auto">
                    <DetailCard title="Relationships" Icon={ShareIcon}>
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

export default VTIPDetails;