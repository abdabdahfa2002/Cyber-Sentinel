
import React, { useState } from 'react';
import { DocumentTextIcon, UploadIcon } from './icons';

interface EventInputProps {
  value: string;
  onChange: (event: React.ChangeEvent<HTMLTextAreaElement>) => void;
  files: File[];
  onFilesChange: (files: File[]) => void;
  onAnalyze: () => void;
  isLoading: boolean;
  onUseExample: () => void;
}

const EventInput: React.FC<EventInputProps> = ({ value, onChange, files, onFilesChange, onAnalyze, isLoading, onUseExample }) => {
  const [activeTab, setActiveTab] = useState<'text' | 'file'>('text');

  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    if (event.target.files) {
      onFilesChange(Array.from(event.target.files));
    }
  };

  const handleDragOver = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
  };

  const handleDrop = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    if (event.dataTransfer.files) {
      onFilesChange(Array.from(event.dataTransfer.files));
    }
  };

  const useExampleAndSwitchTab = () => {
    onUseExample();
    setActiveTab('text');
  };

  return (
    <div className="bg-sentinel-gray-medium rounded-lg shadow-xl border border-sentinel-gray-light">
      <div className="flex border-b border-sentinel-gray-light">
        <button
          onClick={() => setActiveTab('text')}
          className={`flex-1 p-4 font-medium text-sm flex items-center justify-center gap-2 transition-colors ${activeTab === 'text' ? 'bg-sentinel-gray-dark text-sentinel-blue border-b-2 border-sentinel-blue' : 'text-gray-400 hover:bg-sentinel-gray-light/50'}`}
          disabled={isLoading}
        >
          <DocumentTextIcon className="h-5 w-5" />
          Paste Text
        </button>
        <button
          onClick={() => setActiveTab('file')}
          className={`flex-1 p-4 font-medium text-sm flex items-center justify-center gap-2 transition-colors ${activeTab === 'file' ? 'bg-sentinel-gray-dark text-sentinel-blue border-b-2 border-sentinel-blue' : 'text-gray-400 hover:bg-sentinel-gray-light/50'}`}
          disabled={isLoading}
        >
          <UploadIcon className="h-5 w-5" />
          Upload Files
        </button>
      </div>
      
      <div className="p-6">
        {activeTab === 'text' ? (
          <div>
            <label htmlFor="event-log" className="block text-sm font-medium text-gray-300 mb-2">
              Event Log / Description
            </label>
            <textarea
              id="event-log"
              rows={10}
              className="w-full bg-sentinel-gray-dark border border-sentinel-gray-light rounded-md p-3 text-gray-200 focus:ring-2 focus:ring-sentinel-blue focus:border-sentinel-blue transition duration-150 ease-in-out placeholder-gray-500"
              placeholder="Paste your security log, alert details, or incident description here..."
              value={value}
              onChange={onChange}
              disabled={isLoading}
            />
          </div>
        ) : (
          <div>
             <label className="block text-sm font-medium text-gray-300 mb-2">
              Event Files (e.g., JSON, XML, TXT, LOG)
            </label>
            <div
                className="mt-1 flex justify-center px-6 pt-5 pb-6 border-2 border-sentinel-gray-light border-dashed rounded-md"
                onDragOver={handleDragOver}
                onDrop={handleDrop}
            >
              <div className="space-y-1 text-center">
                  <UploadIcon className="mx-auto h-12 w-12 text-gray-400" />
                <div className="flex text-sm text-gray-400">
                  <label htmlFor="file-upload" className="relative cursor-pointer bg-sentinel-gray-medium rounded-md font-medium text-sentinel-blue hover:text-cyan-400 focus-within:outline-none focus-within:ring-2 focus-within:ring-offset-2 focus-within:ring-offset-sentinel-gray-medium focus-within:ring-cyan-500">
                    <span>Upload files</span>
                    <input id="file-upload" name="file-upload" type="file" multiple className="sr-only" onChange={handleFileChange} disabled={isLoading} />
                  </label>
                  <p className="pl-1">or drag and drop</p>
                </div>
                <p className="text-xs text-gray-500">Any text-based files like CVE reports, logs, etc.</p>
              </div>
            </div>
            {files.length > 0 && (
                <div className="mt-4 max-h-28 overflow-y-auto">
                    <h3 className="text-sm font-medium text-gray-300">Selected files:</h3>
                    <ul className="mt-2 space-y-1 list-disc list-inside">
                        {files.map(file => (
                            <li key={file.name} className="text-sm text-gray-400 truncate">
                                {file.name} ({Math.round(file.size / 1024)} KB)
                            </li>
                        ))}
                    </ul>
                </div>
            )}
          </div>
        )}

        <div className="mt-6 flex flex-col sm:flex-row items-center justify-between gap-4">
          <button
              type="button"
              onClick={useExampleAndSwitchTab}
              disabled={isLoading}
              className="text-sm text-sentinel-blue hover:text-cyan-400 disabled:opacity-50 disabled:cursor-not-allowed transition"
          >
              Use Example Log
          </button>
          <button
            onClick={onAnalyze}
            disabled={isLoading}
            className="w-full sm:w-auto flex items-center justify-center px-8 py-3 border border-transparent text-base font-medium rounded-md text-white bg-sentinel-blue hover:bg-cyan-600 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-sentinel-gray-dark focus:ring-cyan-500 disabled:bg-gray-500 disabled:cursor-not-allowed transition duration-300 ease-in-out"
          >
            {isLoading ? (
              <>
                <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                Analyzing...
              </>
            ) : (
              'Analyze Event'
            )}
          </button>
        </div>
      </div>
    </div>
  );
};

export default EventInput;
