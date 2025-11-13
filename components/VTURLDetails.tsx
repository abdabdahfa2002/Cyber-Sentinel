

import React, { useState, useEffect } from 'react';
import { getRelationship } from '../services/virusTotalService';
import type { VTURLReport, VTRelationship, VTFile } from '../types';
import { XCircleIcon, InfoIcon, DocumentDuplicateIcon, ShareIcon } from './icons';

type DetailTab = 'summary' | 'files';

interface VTURLDetailsProps {
  urlReport: VTURLReport;
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

const VTURLDetails: React.FC<VTURLDetailsProps> = ({ urlReport, apiKey, onClose }) => {
    const [activeTab, setActiveTab] = useState<DetailTab>('summary');
    const [isLoading, setIsLoading] = useState<boolean>(false);
    const [downloadedFiles, setDownloadedFiles] = useState<VTFile[]>([]);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        const fetchRelationships = async () => {
            if (activeTab === 'summary') return;
            
            setIsLoading(true);
            setError(null);
            
            try {
                if (activeTab === 'files') {
                    const relationshipData = await getRelationship(apiKey, 'urls', urlReport.attributes.url, 'downloaded_files');
                    setDownloadedFiles(relationshipData as VTFile[]);
                }
            } catch (err) {
                setError(err instanceof Error ? err.message : 'An unknown error occurred.');
            } finally {
                setIsLoading(false);
            }
        };
        fetchRelationships();
    }, [activeTab, apiKey, urlReport.id, urlReport.attributes.url]);

    const renderSummary = () => {
        const { attributes } = urlReport;
        return (
             <div className="space-y-4">
                <DetailCard title="URL Properties" Icon={InfoIcon}>
                    <div className="grid grid-cols-1 gap-4 text-sm">
                        <div><strong className="text-gray-400">Page Title:</strong> <span className="text-cyan-300">{attributes.title || 'N/A'}</span></div>
                        <div><strong className="text-gray-400">Final URL (after redirects):</strong> <a href={attributes.last_final_url} target="_blank" rel="noopener noreferrer" className="text-cyan-300 break-all hover:underline">{attributes.last_final_url || 'N/A'}</a></div>
                        <div><strong className="text-gray-400">Last Response Code:</strong> {attributes.last_http_response_code || 'N/A'}</div>
                    </div>
                </DetailCard>
                <DetailCard title="Categories" Icon={InfoIcon}>
                    {attributes.categories && Object.keys(attributes.categories).length > 0 ? (
                        <div className="flex flex-wrap gap-2">
                            {Object.entries(attributes.categories).map(([key, value]) => (
                                <span key={key} className="px-2 py-1 text-xs font-medium bg-sentinel-gray-light text-cyan-300 rounded-full">
                                    {value} ({key})
                                </span>
                            ))}
                        </div>
                    ) : <p className="text-sm text-gray-400">No categories assigned.</p>}
                </DetailCard>
            </div>
        );
    };

    const renderFiles = () => (
         <div className="overflow-x-auto max-h-80">
            <table className="w-full text-sm text-left">
                <thead className="text-xs text-gray-400 uppercase bg-sentinel-gray-light sticky top-0">
                    <tr>
                        <th className="px-4 py-2">SHA-256</th>
                        <th className="px-4 py-2 text-center">Detections</th>
                        <th className="px-4 py-2">File Name</th>
                        <th className="px-4 py-2">Last Seen</th>
                    </tr>
                </thead>
                <tbody className="text-gray-300">
                    {downloadedFiles.map(file => (
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
    );

    const renderContent = () => {
        if (activeTab === 'summary') return renderSummary();
        if (isLoading) return <LoadingSpinner />;
        if (error) return <ErrorDisplay message={error} />;
        return downloadedFiles.length > 0 ? renderFiles() : <p className="text-sm text-gray-400">No downloaded files found.</p>;
    };

    return (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50 animate-fade-in" onClick={onClose}>
            <div className="bg-sentinel-gray-medium w-full max-w-4xl h-full max-h-[90vh] rounded-xl shadow-2xl border border-sentinel-gray-light flex flex-col" onClick={e => e.stopPropagation()}>
                <div className="flex items-center justify-between p-4 border-b border-sentinel-gray-light">
                    <div>
                        <h2 className="text-xl font-bold text-gray-100">URL Analysis</h2>
                        <p className="text-sm font-mono text-cyan-300 break-all">{urlReport.attributes.url}</p>
                    </div>
                    <button onClick={onClose} className="text-gray-400 hover:text-white"><XCircleIcon className="h-8 w-8" /></button>
                </div>
                <div className="p-4 border-b border-sentinel-gray-light">
                     <div className="flex space-x-2 rounded-lg bg-sentinel-gray-dark p-1">
                       {(['summary', 'files'] as DetailTab[]).map(tab => (
                            <button key={tab} onClick={() => setActiveTab(tab)} className={`w-full rounded-md px-3 py-2 text-sm font-medium text-center transition-colors capitalize ${activeTab === tab ? 'bg-sentinel-blue text-white' : 'text-gray-400 hover:bg-sentinel-gray-light/50'}`}>{tab === 'files' ? 'Downloaded Files' : tab}</button>
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

export default VTURLDetails;