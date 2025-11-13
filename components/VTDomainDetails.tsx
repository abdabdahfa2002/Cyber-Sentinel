

import React, { useState, useEffect } from 'react';
import { getRelationship } from '../services/virusTotalService';
import type { VTDomainReport, VTRelationship, VTFile, VTResolution } from '../types';
import { XCircleIcon, InfoIcon, DocumentDuplicateIcon, ServerIcon } from './icons';
import { useLocalization } from '../contexts/LocalizationContext';

type DetailTab = 'summary' | 'files' | 'ips';

interface VTDomainDetailsProps {
  domainReport: VTDomainReport;
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

const VTDomainDetails: React.FC<VTDomainDetailsProps> = ({ domainReport, apiKey, onClose }) => {
    const { t } = useLocalization();
    const [activeTab, setActiveTab] = useState<DetailTab>('summary');
    const [isLoading, setIsLoading] = useState<boolean>(false);
    const [relatedFiles, setRelatedFiles] = useState<VTFile[]>([]);
    const [resolutions, setResolutions] = useState<VTResolution[]>([]);
    const [filesError, setFilesError] = useState<string | null>(null);
    const [resolutionsError, setResolutionsError] = useState<string | null>(null);

    useEffect(() => {
        const fetchRelationships = async () => {
            setIsLoading(true);
            setFilesError(null);
            setResolutionsError(null);

            // Fetch files (communicating and downloaded)
            try {
                const [communicating, downloaded] = await Promise.all([
                    getRelationship(apiKey, 'domains', domainReport.id, 'communicating_files'),
                    getRelationship(apiKey, 'domains', domainReport.id, 'downloaded_files'),
                ]);
                
                const allFiles = [...communicating as VTFile[], ...downloaded as VTFile[]];
                const uniqueFiles = Array.from(new Map(allFiles.map(file => [file.id, file])).values());
                setRelatedFiles(uniqueFiles);
            } catch (error) {
                setFilesError(error instanceof Error ? error.message : 'An unknown error occurred while fetching files.');
                setRelatedFiles([]);
            }

            // Fetch IP resolutions
            try {
                const res = await getRelationship(apiKey, 'domains', domainReport.id, 'resolutions');
                setResolutions(res as VTResolution[]);
            } catch (error) {
                setResolutionsError(error instanceof Error ? error.message : 'An unknown error occurred while fetching IPs.');
                setResolutions([]);
            }

            setIsLoading(false);
        };
        fetchRelationships();
    }, [apiKey, domainReport.id]);

    const renderSummary = () => (
        <div className="space-y-4">
            <DetailCard title="WHOIS Information" Icon={InfoIcon}>
                <pre className="text-xs text-gray-400 bg-sentinel-gray-dark p-3 rounded-md overflow-x-auto max-h-60">
                    {domainReport.attributes.whois || 'WHOIS data not available.'}
                </pre>
            </DetailCard>
             <DetailCard title="Categories" Icon={InfoIcon}>
                {domainReport.attributes.categories && Object.keys(domainReport.attributes.categories).length > 0 ? (
                    <div className="flex flex-wrap gap-2">
                        {Object.entries(domainReport.attributes.categories).map(([key, value]) => (
                            <span key={key} className="px-2 py-1 text-xs font-medium bg-sentinel-gray-light text-cyan-300 rounded-full">
                                {value}
                            </span>
                        ))}
                    </div>
                ) : <p className="text-sm text-gray-400">No categories assigned.</p>}
            </DetailCard>
        </div>
    );

    const renderFiles = () => (
        <DetailCard title="Associated Files" Icon={DocumentDuplicateIcon}>
            {isLoading ? <LoadingSpinner /> : filesError ? <ErrorDisplay message={filesError} /> : relatedFiles.length > 0 ? (
                <div className="overflow-x-auto max-h-80">
                    <table className="w-full text-sm text-left">
                        <thead className="text-xs text-gray-400 uppercase bg-sentinel-gray-light sticky top-0">
                            <tr>
                                <th className="px-4 py-2">SHA-256</th>
                                <th className="px-4 py-2">Detections</th>
                                <th className="px-4 py-2">File Name</th>
                                <th className="px-4 py-2">Last Seen</th>
                            </tr>
                        </thead>
                        <tbody className="text-gray-300">
                            {relatedFiles.map(file => (
                                <tr key={file.id} className="border-b border-sentinel-gray-light hover:bg-sentinel-gray-light/50">
                                    <td className="px-4 py-2 font-mono text-xs break-all">{file.id}</td>
                                    <td className="px-4 py-2 text-center text-red-400 font-semibold">{file.attributes.last_analysis_stats.malicious}</td>
                                    <td className="px-4 py-2 text-cyan-300 break-all">{file.attributes.meaningful_name || file.attributes.names?.[0] || 'N/A'}</td>
                                    <td className="px-4 py-2">{new Date(file.attributes.last_analysis_date * 1000).toLocaleDateString()}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            ) : <p className="text-sm text-gray-400">No associated files found.</p>}
        </DetailCard>
    );

    const renderResolutions = () => (
         <DetailCard title="IP Resolutions" Icon={ServerIcon}>
            {isLoading ? <LoadingSpinner /> : resolutionsError ? <ErrorDisplay message={resolutionsError} /> : resolutions.length > 0 ? (
                <div className="overflow-x-auto max-h-80">
                    <table className="w-full text-sm text-left">
                        <thead className="text-xs text-gray-400 uppercase bg-sentinel-gray-light sticky top-0">
                            <tr>
                                <th className="px-4 py-2">IP Address</th>
                                <th className="px-4 py-2">Last Seen</th>
                            </tr>
                        </thead>
                        <tbody className="text-gray-300">
                            {resolutions.map(res => (
                                <tr key={res.id} className="border-b border-sentinel-gray-light hover:bg-sentinel-gray-light/50">
                                    <td className="px-4 py-2 font-mono">{res.attributes.ip_address}</td>
                                    <td className="px-4 py-2">{new Date(res.attributes.date * 1000).toLocaleString()}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            ) : <p className="text-sm text-gray-400">No IP resolutions found.</p>}
        </DetailCard>
    );

    const renderContent = () => {
        switch (activeTab) {
            case 'files': return renderFiles();
            case 'ips': return renderResolutions();
            case 'summary':
            default:
                return renderSummary();
        }
    };

    return (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50 animate-fade-in" onClick={onClose}>
            <div className="bg-sentinel-gray-medium w-full max-w-4xl h-full max-h-[90vh] rounded-xl shadow-2xl border border-sentinel-gray-light flex flex-col" onClick={e => e.stopPropagation()}>
                {/* Header */}
                <div className="flex items-center justify-between p-4 border-b border-sentinel-gray-light flex-shrink-0">
                    <div>
                        <h2 className="text-xl font-bold text-gray-100">Domain Analysis</h2>
                        <p className="text-sm font-mono text-cyan-300">{domainReport.id}</p>
                    </div>
                    <button onClick={onClose} className="text-gray-400 hover:text-white">
                        <XCircleIcon className="h-8 w-8" />
                    </button>
                </div>
                {/* Tabs */}
                <div className="p-4 border-b border-sentinel-gray-light flex-shrink-0">
                    <div className="flex space-x-2 rounded-lg bg-sentinel-gray-dark p-1">
                        {(['summary', 'files', 'ips'] as DetailTab[]).map(tab => (
                            <button
                                key={tab}
                                onClick={() => setActiveTab(tab)}
                                className={`w-full rounded-md px-3 py-2 text-sm font-medium text-center transition-colors capitalize ${activeTab === tab ? 'bg-sentinel-blue text-white shadow' : 'text-gray-400 hover:bg-sentinel-gray-light/50'}`}
                            >
                                {tab === 'ips' ? 'IP Resolutions' : tab === 'files' ? 'Associated Files' : 'Summary'}
                            </button>
                        ))}
                    </div>
                </div>
                {/* Content */}
                <div className="p-6 overflow-y-auto">
                    {renderContent()}
                </div>
            </div>
            <style>{`
                @keyframes fade-in {
                    from { opacity: 0; transform: scale(0.95); }
                    to { opacity: 1; transform: scale(1); }
                }
                .animate-fade-in {
                    animation: fade-in 0.2s ease-out forwards;
                }
            `}</style>
        </div>
    );
};

export default VTDomainDetails;