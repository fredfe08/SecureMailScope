import { useState } from 'react';
import { Loader2, AlertTriangle } from 'lucide-react';
import { Sidebar, type NavKey } from './components/Sidebar';
import { MainHeader } from './components/MainHeader';
import { OverviewDetail } from './components/OverviewDetail';
import { SectionDetail } from './components/SectionDetail';
import { AiSummaryPanel } from './components/AiSummaryPanel';
import { EmptyState } from './components/EmptyState';
import { analyzePcapFile, PcapParseError } from './lib/pcap';
import { buildReport } from './lib/report/buildReport';
import type { ScanReport, SectionResult } from './types/report';

const SECTION_TITLES: Record<SectionResult['key'], string> = {
  spf: 'SPF',
  dkim: 'DKIM',
  dmarc: 'DMARC',
  tls: 'TLS',
  domain: 'Domain',
};

export default function App() {
  const [report, setReport] = useState<ScanReport | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<NavKey>('overview');

  const runScan = async (domain: string, file: File | null) => {
    setIsScanning(true);
    setError(null);
    try {
      const pcap = file ? await analyzePcapFile(file) : null;
      const result = await buildReport(domain, pcap);
      setReport(result);
      setSelected('overview');
    } catch (err) {
      if (err instanceof PcapParseError) {
        setError(err.message);
      } else {
        setError('Something went wrong running the scan. Check the domain and try again.');
      }
    } finally {
      setIsScanning(false);
    }
  };

  const activeSection = report?.sections.find((s) => s.key === selected);
  const title =
    selected === 'overview' ? 'Overview' : selected === 'ai' ? 'AI summary' : SECTION_TITLES[selected as SectionResult['key']];

  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar report={report} selected={selected} onSelect={setSelected} onScan={runScan} isScanning={isScanning} />

      <div className="flex min-w-0 flex-1 flex-col">
        <MainHeader title={title} report={report} />

        <main className="flex-1 overflow-y-auto px-8 py-6">
          {error && (
            <div className="mb-5 flex items-start gap-3 rounded-lg border border-danger/30 bg-danger/5 px-4 py-3">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-danger" />
              <p className="text-sm text-danger">{error}</p>
            </div>
          )}

          {isScanning && (
            <div className="flex items-center gap-2 rounded-lg border border-border bg-panel px-5 py-6 text-sm text-muted">
              <Loader2 className="h-4 w-4 animate-spin" />
              Running SPF, DKIM, DMARC and DNS checks{report?.pcap ? ', and reading the capture' : ''}...
            </div>
          )}

          {!isScanning && !report && <EmptyState />}

          {!isScanning && report && selected === 'overview' && <OverviewDetail report={report} />}

          {!isScanning && report && selected === 'ai' && <AiSummaryPanel report={report} />}

          {!isScanning && report && activeSection && <SectionDetail section={activeSection} pcap={report.pcap} />}
        </main>

        <footer className="border-t border-border px-8 py-3">
          <p className="text-xs text-muted">
            SPF/DKIM/DMARC checks query live DNS. DKIM detection probes common selector names only —
            a domain can still sign mail under a selector Postflight doesn't know to check.
          </p>
        </footer>
      </div>
    </div>
  );
}
