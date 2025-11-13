

import React, { useState } from 'react';
import { getDomainReport, getFileReport, getIPReport, getURLReport, uploadFileForAnalysis, getAnalysisReport } from '../services/virusTotalService';
import type { VTReport, VTDomainReport, VTFileReport, VTIPAddressReport, VTURLReport } from '../types';
import { DocumentTextIcon, DownloadIcon, UploadIcon, InfoIcon, EyeIcon, EyeSlashIcon, ChevronRightIcon, GlobeAltIcon, FingerPrintIcon, LinkIcon, ServerIcon, DocumentArrowUpIcon } from './icons';
import VTDomainDetails from './VTDomainDetails';
import VTFileDetails from './VTFileDetails';
import VTIPDetails from './VTIPDetails';
import VTURLDetails from './VTURLDetails';
import { useLocalization } from '../contexts/LocalizationContext';

type InputTab = 'text' | 'file';
type ScanSpeed = 'slow' | 'medium' | 'fast';
type ScanType = 'domain' | 'hash' | 'ip' | 'url' | 'file';

const DEFAULT_VT_API_KEY = '75d811d12cf0a51a4b982dcfd3854a9e6f7634c04f93b6d7a54781327ed59033';

const VTScanner: React.FC = () => {
    const { t } = useLocalization();
    const [apiKey, setApiKey] = useState<string>('');
    const [isKeyVisible, setIsKeyVisible] = useState(false);
    const [scannerInput, setScannerInput] = useState<string>('');
    const [results, setResults] = useState<VTReport[]>([]);
    const [isLoading, setIsLoading] = useState<boolean>(false);
    const [status, setStatus] = useState<string>(t('ready'));
    const [error, setError] = useState<string | null>(null);
    const [activeInputTab, setActiveInputTab] = useState<InputTab>('text');
    const [scanSpeed, setScanSpeed] = useState<ScanSpeed>('slow');
    const [scanType, setScanType] = useState<ScanType>('domain');
    const [selectedReport, setSelectedReport] = useState<VTReport | null>(null);
    const [fileToScan, setFileToScan] = useState<File | null>(null);
    
    const SPEED_CONFIG = {
        slow: { label: t('speedSlow_label'), description: t('speedSlow_desc'), batchSize: 4, delay: 60000 },
        medium: { label: t('speedMedium_label'), description: t('speedMedium_desc'), batchSize: 10, delay: 10000 },
        fast: { label: t('speedFast_label'), description: t('speedFast_desc'), batchSize: 20, delay: 5000 },
    };

    const SCAN_TYPES_CONFIG: { [key in ScanType]: { label: string; placeholder: string; enabled: boolean, Icon: React.FC<{className?: string}> } } = {
        domain: { label: t('domains'), placeholder: t('domains_placeholder'), enabled: true, Icon: GlobeAltIcon },
        hash: { label: t('fileHashes'), placeholder: t('hashes_placeholder'), enabled: true, Icon: FingerPrintIcon },
        ip: { label: t('ipAddresses'), placeholder: t('ips_placeholder'), enabled: true, Icon: ServerIcon },
        url: { label: t('urls'), placeholder: t('urls_placeholder'), enabled: true, Icon: LinkIcon },
        file: { label: t('fileScan'), placeholder: t('fileScan_placeholder'), enabled: true, Icon: DocumentArrowUpIcon },
    };

    const parseInput = (inputText: string, scanType: ScanType): string[] => {
        let items = inputText.split(/[,\s\n\t]+/).map(item => item.trim()).filter(Boolean);
        
        if (scanType === 'domain') {
            items = items.map(line => {
                 try {
                    if (line.match(/^https?:\/\//)) {
                        return new URL(line).hostname;
                    }
                    return line;
                } catch (e) {
                    return line;
                }
            }).filter(d => d && d.includes('.'));
        }
        return [...new Set(items)];
    };

    const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

    const isDomainReport = (report: VTReport): report is VTDomainReport => report.type === 'domain';
    const isFileReport = (report: VTReport): report is VTFileReport => report.type === 'file';
    const isIPReport = (report: VTReport): report is VTIPAddressReport => report.type === 'ip_address';
    const isURLReport = (report: VTReport): report is VTURLReport => report.type === 'url';

    const InfoBox: React.FC<{ children: React.ReactNode }> = ({ children }) => (
        <div className="p-4 bg-blue-900/50 border border-blue-700 rounded-lg text-blue-300 text-sm">
            <div className="flex">
                <InfoIcon className="h-5 w-5 me-3 flex-shrink-0 mt-0.5" />
                <div>{children}</div>
            </div>
        </div>
    );

    const handleIndicatorListFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
        const file = event.target.files?.[0];
        if (!file) return;

        const reader = new FileReader();
        reader.onload = (e) => {
            const text = e.target?.result as string;
            setScannerInput(text);
            setStatus(`Loaded ${scanType}s from ${file.name}`);
        };
        reader.readAsText(file);
    };

    const handleScanFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
        const file = event.target.files?.[0];
        if (!file) return;
        setFileToScan(file);
        setStatus(`Selected file: ${file.name}`);
    };
    
    const handleScan = async () => {
        const keyToUse = apiKey.trim() || DEFAULT_VT_API_KEY;
        if (!apiKey.trim()) setApiKey(keyToUse);

        if (scanType === 'file') {
            if (!fileToScan) {
                setError(t('error_selectFile'));
                return;
            }
            setIsLoading(true);
            setError(null);
            setResults([]);
            try {
                setStatus(t('uploadingFile', { fileName: fileToScan.name }));
                const analysisId = await uploadFileForAnalysis(keyToUse, fileToScan);
                
                setStatus(t('analysisPending'));
                
                let analysisReport;
                let isCompleted = false;
                const startTime = Date.now();
                const timeout = 300000; // 5 minutes timeout

                while(!isCompleted && (Date.now() - startTime < timeout)) {
                    analysisReport = await getAnalysisReport(keyToUse, analysisId);
                    if (analysisReport?.data?.attributes?.status === 'completed') {
                        isCompleted = true;
                    } else {
                        await sleep(15000); // Poll every 15 seconds
                        setStatus(t('analysisInProgress'));
                    }
                }

                if (!isCompleted) {
                    throw new Error('Analysis timed out after 5 minutes.');
                }
                
                setStatus(t('analysisCompleteFetchingReport'));
                
                // Robustly get the file hash from the analysis report
                const fileHash = analysisReport.data?.relationships?.item?.data?.id || analysisReport.meta?.file_info?.sha256;

                if (!fileHash) {
                    console.error("Could not extract file hash from completed analysis report:", analysisReport);
                    throw new Error('Analysis completed, but could not retrieve the file hash from the report.');
                }

                const finalReport = await getFileReport(keyToUse, fileHash);
                
                setResults([{ ...finalReport, error: 'Success' }]);
                setStatus(t('scanCompleteForFile', { fileName: fileToScan.name }));
            } catch (err) {
                const error = err instanceof Error ? err : new Error(String(err));
                let errorMessage = error.message;
                if (error instanceof TypeError && error.message === 'Failed to fetch') {
                    errorMessage = 'Network Error. The public CORS proxy or VirusTotal API might be temporarily unavailable. Please try again later.';
                }
                setError(errorMessage);
                setStatus('Scan failed.');
            } finally {
                setIsLoading(false);
            }
            return;
        }

        const items = parseInput(scannerInput, scanType);
        if (items.length === 0) {
            setError(`No valid ${scanType}s found in the input. Please check your list.`);
            return;
        }

        setIsLoading(true);
        setError(null);
        setResults([]);
        
        const { batchSize, delay } = SPEED_CONFIG[scanSpeed];
        
        const itemBatches: string[][] = [];
        for (let i = 0; i < items.length; i += batchSize) {
            itemBatches.push(items.slice(i, i + batchSize));
        }

        let allResults: VTReport[] = [];

        for (let i = 0; i < itemBatches.length; i++) {
            const batch = itemBatches[i];
            setStatus(`Scanning batch ${i + 1}/${itemBatches.length} (${batch.length} ${scanType}s)...`);

            const batchPromises = batch.map(item => {
                let apiCall: Promise<VTReport>;
                switch(scanType) {
                    case 'domain': apiCall = getDomainReport(keyToUse, item); break;
                    case 'hash': apiCall = getFileReport(keyToUse, item); break;
                    case 'ip': apiCall = getIPReport(keyToUse, item); break;
                    case 'url': apiCall = getURLReport(keyToUse, item); break;
                }

                return apiCall
                    .then(report => ({ ...report, error: 'Success' }))
                    .catch((err: Error) => {
                        let errorMessage = err.message || 'Failed to fetch report';
                        if (err instanceof TypeError && err.message === 'Failed to fetch') {
                            errorMessage = 'Network Error. The public CORS proxy or VirusTotal API might be temporarily unavailable. Please try again later.';
                        }
                        return {
                            type: scanType,
                            id: item,
                            attributes: {} as any,
                            error: errorMessage,
                        } as VTReport;
                    })
            });

            const batchResults = await Promise.all(batchPromises);
            allResults = [...allResults, ...batchResults];
            setResults(allResults);

            if (i < itemBatches.length - 1) {
                setStatus(`Batch ${i + 1} complete. Waiting ${delay / 1000}s for API rate limit reset...`);
                await sleep(delay);
            }
        }

        setStatus(`Scan complete. Analyzed ${items.length} ${scanType}s.`);
        setIsLoading(false);
    };
    
    const handleSaveCSV = () => {
        if (results.length === 0) return;

        const headers: string[] = ['Indicator', 'Status', 'Malicious', 'Suspicious', 'Harmless', 'Context', 'Last Scan Date'];
        const csvRows = [headers.join(',')];

        results.forEach(res => {
            const stats = res.attributes?.last_analysis_stats;
            const lastScan = res.attributes?.last_analysis_date ? new Date(res.attributes.last_analysis_date * 1000).toISOString().split('T')[0] : 'N/A';
            let context = 'N/A';
            if (isFileReport(res)) context = res.attributes.meaningful_name || res.attributes.names?.[0] || 'N/A';
            if (isIPReport(res)) context = res.attributes.as_owner || 'N/A';
            if (isURLReport(res)) context = res.attributes.title || 'N/A';
            if (isDomainReport(res)) context = res.attributes.registrar || 'N/A';
            
            const rowData = [
                res.id, res.error || 'N/A', stats?.malicious ?? 'N/A', stats?.suspicious ?? 'N/A',
                stats?.harmless ?? 'N/A', context, lastScan
            ];

            const row = rowData.map(val => `"${String(val).replace(/"/g, '""')}"`).join(',');
            csvRows.push(row);
        });

        const csvString = csvRows.join('\n');
        const blob = new Blob([csvString], { type: 'text/csv;charset=utf-8;' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `vt-${scanType}-report-${new Date().toISOString()}.csv`;
        link.click();
        URL.revokeObjectURL(url);
    };

    const getRowClass = (result: VTReport) => {
        if (result.error !== 'Success') return 'bg-gray-700/50 hover:bg-gray-600/50';
        const stats = result.attributes.last_analysis_stats;
        if (!stats) return 'bg-sentinel-gray-dark hover:bg-sentinel-gray-light';
        if (stats.malicious > 0) return 'bg-red-900/50 hover:bg-red-800/50';
        if (stats.suspicious > 0) return 'bg-yellow-900/50 hover:bg-yellow-800/50';
        return 'bg-sentinel-gray-dark hover:bg-sentinel-gray-light';
    };

    return (
        <div className="max-w-6xl mx-auto space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <InfoBox>
                    <p className="font-bold mb-1">{t('noteOnSpeed')}</p>
                    <p>{t('noteOnConnectivity')}</p>
                </InfoBox>
                
                <div className="bg-sentinel-gray-medium rounded-lg shadow-lg border border-sentinel-gray-light p-4">
                    <h2 className="text-lg font-bold text-gray-200 mb-2">{t('scannerConfig')}</h2>
                    <div className="space-y-4">
                        <div>
                            <label htmlFor="api-key" className="block text-sm font-medium text-gray-300 mb-1">{t('vtApiKey')}</label>
                            <div className="relative">
                                <input
                                    id="api-key"
                                    type={isKeyVisible ? 'text' : 'password'}
                                    value={apiKey}
                                    onChange={(e) => setApiKey(e.target.value)}
                                    placeholder={t('vtApiKey_placeholder')}
                                    className="w-full bg-sentinel-gray-dark border border-sentinel-gray-light rounded-md p-2 text-gray-200 text-sm focus:ring-sentinel-blue"
                                />
                                <button onClick={() => setIsKeyVisible(!isKeyVisible)} className="absolute inset-y-0 end-0 pe-3 flex items-center text-gray-400 hover:text-white">
                                    {isKeyVisible ? <EyeSlashIcon className="h-5 w-5" /> : <EyeIcon className="h-5 w-5" />}
                                </button>
                            </div>
                            <p className="text-xs text-gray-500 mt-1">{t('keyNotStored')}</p>
                        </div>
                        {scanType !== 'file' && (
                            <div>
                                <label className="block text-sm font-medium text-gray-300 mb-1">{t('scanSpeed')}</label>
                                <div className="flex space-x-2 rounded-lg bg-sentinel-gray-dark p-1">
                                    {Object.entries(SPEED_CONFIG).map(([key, config]) => (
                                        <button
                                            key={key}
                                            onClick={() => setScanSpeed(key as ScanSpeed)}
                                            className={`w-full rounded-md px-3 py-2 text-sm font-medium text-center transition-colors ${scanSpeed === key ? 'bg-sentinel-blue text-white shadow' : 'text-gray-400 hover:bg-sentinel-gray-light/50'}`}
                                        >
                                            {config.label} <span className="text-xs opacity-75">({config.description})</span>
                                        </button>
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>
                </div>
            </div>

            <div className="bg-sentinel-gray-medium rounded-lg shadow-xl border border-sentinel-gray-light">
                <div className="flex border-b border-sentinel-gray-light">
                    {Object.entries(SCAN_TYPES_CONFIG).map(([key, config]) => (
                        <button
                            key={key}
                            onClick={() => setScanType(key as ScanType)}
                            className={`flex-1 p-4 font-medium text-sm flex items-center justify-center gap-2 transition-colors ${scanType === key ? 'bg-sentinel-gray-dark text-sentinel-blue border-b-2 border-sentinel-blue' : 'text-gray-400 hover:bg-sentinel-gray-light/50'}`}
                            disabled={isLoading || !config.enabled}
                        >
                            <config.Icon className="h-5 w-5" />
                            {config.label}
                        </button>
                    ))}
                </div>

                <div className="p-6">
                    {scanType === 'file' ? (
                         <div className="flex justify-center items-center w-full">
                            <label htmlFor="file-upload-scanner" className="flex flex-col justify-center items-center w-full h-40 bg-sentinel-gray-dark rounded-lg border-2 border-sentinel-gray-light border-dashed cursor-pointer hover:bg-sentinel-gray-light">
                                <UploadIcon className="w-10 h-10 mb-3 text-gray-400" />
                                {fileToScan ? (
                                    <p className="text-sm text-sentinel-green">{fileToScan.name}</p>
                                ) : (
                                    <>
                                        <p className="mb-2 text-sm text-gray-400"><span className="font-semibold">{t('clickToUpload')}</span> {t('orDragAndDrop')}</p>
                                        <p className="text-xs text-gray-500">{t('fileScan_placeholder')}</p>
                                    </>
                                )}
                                <input id="file-upload-scanner" type="file" className="hidden" onChange={handleScanFileChange} disabled={isLoading}/>
                            </label>
                        </div>
                    ) : (
                        <>
                            <div className="flex border-b border-sentinel-gray-light mb-4">
                                <button onClick={() => setActiveInputTab('text')} className={`flex-1 p-3 text-sm font-medium ${activeInputTab === 'text' ? 'text-sentinel-blue border-b-2 border-sentinel-blue' : 'text-gray-400'}`}><DocumentTextIcon className="h-5 w-5 inline me-2"/>{t('pasteList')}</button>
                                <button onClick={() => setActiveInputTab('file')} className={`flex-1 p-3 text-sm font-medium ${activeInputTab === 'file' ? 'text-sentinel-blue border-b-2 border-sentinel-blue' : 'text-gray-400'}`}><UploadIcon className="h-5 w-5 inline me-2"/>{t('uploadFile')}</button>
                            </div>

                            {activeInputTab === 'text' ? (
                                <textarea
                                    rows={8}
                                    className="w-full bg-sentinel-gray-dark border border-sentinel-gray-light rounded-md p-3 text-gray-200 focus:ring-2 focus:ring-sentinel-blue placeholder-gray-500"
                                    placeholder={SCAN_TYPES_CONFIG[scanType].placeholder}
                                    value={scannerInput}
                                    onChange={(e) => setScannerInput(e.target.value)}
                                    disabled={isLoading}
                                />
                            ) : (
                                <div className="flex justify-center items-center w-full">
                                    <label htmlFor="file-upload-scanner-list" className="flex flex-col justify-center items-center w-full h-32 bg-sentinel-gray-dark rounded-lg border-2 border-sentinel-gray-light border-dashed cursor-pointer hover:bg-sentinel-gray-light">
                                        <UploadIcon className="w-10 h-10 mb-3 text-gray-400" />
                                        <p className="mb-2 text-sm text-gray-400">{t('clickToUpload')}</p>
                                        <p className="text-xs text-gray-500">{t('upload_desc')}</p>
                                        <input id="file-upload-scanner-list" type="file" className="hidden" accept=".txt,.csv" onChange={handleIndicatorListFileChange} disabled={isLoading}/>
                                    </label>
                                </div>
                            )}
                        </>
                    )}

                    <div className="mt-6 flex flex-col sm:flex-row items-center justify-between gap-4">
                        <div className="text-sm text-gray-400">{t('status')}: <span className="font-semibold text-gray-300">{status}</span></div>
                        <button
                            onClick={handleScan}
                            disabled={isLoading || (scanType === 'file' ? !fileToScan : !scannerInput.trim())}
                            className="w-full sm:w-auto flex items-center justify-center px-8 py-3 border border-transparent text-base font-medium rounded-md text-white bg-sentinel-blue hover:bg-cyan-600 disabled:opacity-50"
                        >
                            {isLoading ? (
                                <>
                                    <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
                                    {t('scanning')}...
                                </>
                            ) : t('scan')}
                        </button>
                    </div>
                </div>
            </div>
            
            {error && (
                <div className="p-4 bg-red-900/50 border border-red-700 rounded-lg text-red-300 text-center">
                    <p className="font-bold">{t('analysisError')}</p>
                    <p>{error}</p>
                </div>
            )}

            <div className="bg-sentinel-gray-medium rounded-lg shadow-xl border border-sentinel-gray-light p-6">
                <div className="flex justify-between items-center mb-4">
                    <h2 className="text-xl font-bold text-gray-100">{t('scanResults')}</h2>
                    <button
                        onClick={handleSaveCSV}
                        disabled={results.length === 0}
                        className="flex items-center text-sm bg-sentinel-gray-dark hover:bg-sentinel-gray-light text-white px-3 py-1 rounded-md transition disabled:opacity-50"
                    >
                        <DownloadIcon className="h-4 w-4 me-2" />
                        {t('saveAsCsv')}
                    </button>
                </div>
                
                {results.length > 0 ? (
                    <div className="overflow-x-auto max-h-[500px]">
                        <table className="w-full text-sm text-left">
                            <thead className="text-xs text-gray-400 uppercase bg-sentinel-gray-dark sticky top-0">
                                <tr>
                                    <th className="px-4 py-2">Indicator</th>
                                    <th className="px-4 py-2 text-center">Malicious</th>
                                    <th className="px-4 py-2 text-center">Suspicious</th>
                                    <th className="px-4 py-2 text-center">Harmless</th>
                                    <th className="px-4 py-2">Context / Owner</th>
                                    <th className="px-4 py-2"></th>
                                </tr>
                            </thead>
                            <tbody>
                                {results.map((res, index) => (
                                    <tr key={`${res.id}-${index}`} className={`${getRowClass(res)} transition-colors`}>
                                        <td className="px-4 py-2 font-mono text-xs break-all">{isFileReport(res) ? res.attributes.meaningful_name || res.id : res.id}</td>
                                        <td className="px-4 py-2 text-center font-bold text-red-400">{res.attributes.last_analysis_stats?.malicious ?? 'N/A'}</td>
                                        <td className="px-4 py-2 text-center font-bold text-yellow-400">{res.attributes.last_analysis_stats?.suspicious ?? 'N/A'}</td>
                                        <td className="px-4 py-2 text-center font-bold text-green-400">{res.attributes.last_analysis_stats?.harmless ?? 'N/A'}</td>
                                        <td className="px-4 py-2 text-gray-400 text-xs truncate max-w-xs">
                                            {isDomainReport(res) && res.attributes.registrar}
                                            {isFileReport(res) && (res.attributes.type_description || 'N/A')}
                                            {isIPReport(res) && res.attributes.as_owner}
                                            {isURLReport(res) && res.attributes.title}
                                        </td>
                                        <td className="px-4 py-2 text-right">
                                            <button onClick={() => setSelectedReport(res)} className="text-sentinel-blue hover:text-cyan-400 disabled:opacity-50" disabled={res.error !== 'Success'}>
                                                <ChevronRightIcon className="h-5 w-5" />
                                            </button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                ) : (
                    <p className="text-center text-gray-500 py-8">{t('noResults')}</p>
                )}
            </div>
            
            {selectedReport && isDomainReport(selectedReport) && <VTDomainDetails domainReport={selectedReport} apiKey={apiKey || DEFAULT_VT_API_KEY} onClose={() => setSelectedReport(null)} />}
            {selectedReport && isFileReport(selectedReport) && <VTFileDetails fileReport={selectedReport} apiKey={apiKey || DEFAULT_VT_API_KEY} onClose={() => setSelectedReport(null)} />}
            {selectedReport && isIPReport(selectedReport) && <VTIPDetails ipReport={selectedReport} apiKey={apiKey || DEFAULT_VT_API_KEY} onClose={() => setSelectedReport(null)} />}
            {selectedReport && isURLReport(selectedReport) && <VTURLDetails urlReport={selectedReport} apiKey={apiKey || DEFAULT_VT_API_KEY} onClose={() => setSelectedReport(null)} />}

        </div>
    );
};

export default VTScanner;