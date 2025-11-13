
import React from 'react';
import type { MitreAttack } from '../types';
import { TargetIcon } from './icons';

interface MitreAttackSectionProps {
  tactic: MitreAttack;
  technique: MitreAttack;
}

const Card: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <div className="bg-sentinel-gray-medium rounded-lg shadow-lg p-6 border border-sentinel-gray-light h-full">
    {children}
  </div>
);

const MitreAttackSection: React.FC<MitreAttackSectionProps> = ({ tactic, technique }) => {
  return (
    <Card>
      <h2 className="text-xl font-bold text-gray-100 mb-4 flex items-center">
        <TargetIcon className="h-6 w-6 mr-3 text-sentinel-blue" />
        MITRE ATT&CK&reg; Mapping
      </h2>
      <div className="space-y-4">
        <div>
          <h3 className="font-semibold text-gray-300">Tactic</h3>
          <div className="mt-1 p-3 bg-sentinel-gray-dark rounded-md border-l-4 border-sentinel-blue">
            <p className="font-mono text-sm text-sentinel-green">{tactic.id}: {tactic.name}</p>
            <p className="text-sm text-gray-400 mt-1">{tactic.description}</p>
          </div>
        </div>
        <div>
          <h3 className="font-semibold text-gray-300">Technique</h3>
          <div className="mt-1 p-3 bg-sentinel-gray-dark rounded-md border-l-4 border-sentinel-blue">
            <p className="font-mono text-sm text-sentinel-green">{technique.id}: {technique.name}</p>
            <p className="text-sm text-gray-400 mt-1">{technique.description}</p>
          </div>
        </div>
      </div>
    </Card>
  );
};

export default MitreAttackSection;
