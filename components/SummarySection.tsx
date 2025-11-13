
import React from 'react';
import { AlertTriangleIcon, InfoIcon } from './icons';

interface SummarySectionProps {
  summary: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical' | 'Informational';
}

const severityConfig = {
    Informational: {
        color: 'text-blue-400',
        bgColor: 'bg-blue-900/50',
        borderColor: 'border-blue-700',
    },
    Low: {
        color: 'text-green-400',
        bgColor: 'bg-green-900/50',
        borderColor: 'border-green-700',
    },
    Medium: {
        color: 'text-yellow-400',
        bgColor: 'bg-yellow-900/50',
        borderColor: 'border-yellow-700',
    },
    High: {
        color: 'text-orange-400',
        bgColor: 'bg-orange-900/50',
        borderColor: 'border-orange-700',
    },
    Critical: {
        color: 'text-red-400',
        bgColor: 'bg-red-900/50',
        borderColor: 'border-red-700',
    },
};

const Card: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <div className="bg-sentinel-gray-medium rounded-lg shadow-lg p-6 border border-sentinel-gray-light">
    {children}
  </div>
);

const SummarySection: React.FC<SummarySectionProps> = ({ summary, severity }) => {
  const config = severityConfig[severity] || severityConfig.Informational;

  return (
    <Card>
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between mb-4">
        <h2 className="text-xl font-bold text-gray-100 flex items-center mb-2 sm:mb-0">
          <InfoIcon className="h-6 w-6 mr-3 text-sentinel-blue" />
          AI Analysis Summary
        </h2>
        <div className={`flex items-center px-3 py-1 rounded-full text-sm font-semibold ${config.bgColor} ${config.color} border ${config.borderColor}`}>
          <AlertTriangleIcon className="h-4 w-4 mr-2" />
          Severity: {severity}
        </div>
      </div>
      <p className="text-gray-300 leading-relaxed">{summary}</p>
    </Card>
  );
};

export default SummarySection;
