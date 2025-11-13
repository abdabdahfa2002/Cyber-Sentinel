
import React from 'react';
import type { AnalysisResult } from '../types';
import SummarySection from './SummarySection';
import IocSection from './IocSection';
import MitreAttackSection from './MitreAttackSection';
import ChecklistSection from './ChecklistSection';
import TimelineSection from './TimelineSection';

interface AnalysisDashboardProps {
  result: AnalysisResult;
}

const AnalysisDashboard: React.FC<AnalysisDashboardProps> = ({ result }) => {
  return (
    <div className="space-y-8">
      <SummarySection summary={result.summary} severity={result.estimated_severity} />
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <IocSection iocs={result.indicators_of_compromise} />
        <MitreAttackSection tactic={result.attack_tactic} technique={result.attack_technique} />
      </div>
      <TimelineSection events={result.timeline_events} />
      <ChecklistSection checklist={result.investigation_checklist} />
    </div>
  );
};

export default AnalysisDashboard;
