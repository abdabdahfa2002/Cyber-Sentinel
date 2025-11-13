
import React, { useState } from 'react';
import type { AnalysisResult, Case } from '../types';
import { analyzeEvent } from '../services/geminiService';
import EventInput from './EventInput';
import AnalysisDashboard from './AnalysisDashboard';
import { View } from './MainMenu';
import { ArrowLeftIcon } from './icons';
import { useLocalization } from '../contexts/LocalizationContext';

interface AIAnalystProps {
  activeCase: Case | null;
  onAnalysisComplete: (caseId: string | null, result: AnalysisResult) => void;
  setActiveView: (view: View) => void;
}

const AIAnalyst: React.FC<AIAnalystProps> = ({ activeCase, onAnalysisComplete, setActiveView }) => {
  const { t } = useLocalization();
  const [logInput, setLogInput] = useState<string>('');
  const [files, setFiles] = useState<File[]>([]);
  const [analysisResult, setAnalysisResult] = useState<AnalysisResult | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const handleAnalyze = async () => {
    if (!logInput.trim() && files.length === 0) {
      setError(t('error_enterLogOrFile'));
      return;
    }

    setIsLoading(true);
    setError(null);
    setAnalysisResult(null);

    try {
      let contentToAnalyze = '';
      if (files.length > 0) {
        const fileContents = await Promise.all(
          files.map(file => {
            return new Promise<string>((resolve, reject) => {
              const reader = new FileReader();
              reader.onload = (event) => {
                const text = event.target?.result as string;
                resolve(`--- START OF FILE: ${file.name} ---\n${text}\n--- END OF FILE: ${file.name} ---`);
              };
              reader.onerror = (error) => reject(error);
              reader.readAsText(file);
            });
          })
        );
        contentToAnalyze = fileContents.join('\n\n');
      } else {
        contentToAnalyze = logInput;
      }
      
      const result = await analyzeEvent(contentToAnalyze);
      setAnalysisResult(result);
      // Automatically "add" the artifact once analysis is done
      onAnalysisComplete(activeCase?.id || null, result);

    } catch (err) {
      console.error(err);
      setError(t('error_analysisFailed'));
    } finally {
      setIsLoading(false);
    }
  };
  
  const exampleLog = `At 2024-08-15 14:35:10 UTC, a user 'j.doe' on workstation 'DESKTOP-ABC' received a phishing email with the subject 'Urgent Invoice'. The user opened an attached document 'invoice_details.docm'. A PowerShell process was spawned shortly after, making a network connection to the IP address 198.51.100.55 over port 443. The PowerShell command was heavily obfuscated. It then downloaded a file 'payload.exe' to C:\\Users\\j.doe\\AppData\\Local\\Temp and executed it. The SHA256 hash of payload.exe is 8c5c3c3a5e8f8f9f7e7d6c5b4a3a2a1a0b9b8b7b6c5c4c3c2c1c0c9c8c7c6c5c. The executable established persistence via a new scheduled task named 'SystemUpdate'. It began communicating with a command and control server at 'update.malicious-domain.net'.`;
  
  const handleUseExample = () => {
    setLogInput(exampleLog);
    setFiles([]); // Clear any selected files when using an example
  };

  return (
    <div className="max-w-4xl mx-auto">
        {activeCase && (
            <button 
                onClick={() => setActiveView('casebook')} 
                className="flex items-center text-sm text-sentinel-blue hover:text-cyan-400 mb-6 transition-colors"
            >
                <ArrowLeftIcon className="h-4 w-4 me-2" />
                {t('backToCase')}: {activeCase.name}
            </button>
        )}
        <p className="text-center text-gray-400 mb-6">
            {activeCase 
                ? t('aiAnalyst_instructions_activeCase')
                : t('aiAnalyst_instructions_newCase')
            }
        </p>
        
        {!analysisResult && (
             <EventInput 
                value={logInput}
                onChange={(e) => setLogInput(e.target.value)}
                files={files}
                onFilesChange={setFiles}
                onAnalyze={handleAnalyze}
                isLoading={isLoading}
                onUseExample={handleUseExample}
            />
        )}

        {error && (
            <div className="mt-6 p-4 bg-red-900/50 border border-red-700 rounded-lg text-red-300 text-center">
                <p className="font-bold">{t('analysisError')}</p>
                <p>{error}</p>
            </div>
        )}
        
        {isLoading && (
            <div className="mt-8 flex flex-col items-center justify-center space-y-4">
                <div className="w-16 h-16 border-4 border-dashed rounded-full animate-spin border-sentinel-blue"></div>
                <p className="text-sentinel-blue text-lg">{t('aiAnalyzingEvent')}</p>
                <p className="text-gray-400">{t('resultWillBeAdded')}</p>
            </div>
        )}

        {analysisResult && !isLoading && (
            <div className="mt-8">
                <div className="bg-sentinel-gray-medium rounded-lg shadow-lg p-6 border border-sentinel-gray-light mb-8 text-center">
                    <h2 className="text-xl font-bold text-green-400 mb-2">{t('analysisComplete')}</h2>
                    <p className="text-gray-300">{t('analysisSavedToCase')}</p>
                </div>
                <AnalysisDashboard result={analysisResult} />
            </div>
        )}
    </div>
  );
};

export default AIAnalyst;
