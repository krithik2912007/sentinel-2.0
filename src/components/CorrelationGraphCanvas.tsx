import React, { useEffect, useRef, useState } from 'react';
import { CorrelationGraphData, GraphNode, GraphLink } from '../types';
import { Share2, RefreshCw, ZoomIn, ZoomOut, Info } from 'lucide-react';

interface CorrelationGraphCanvasProps {
  data: CorrelationGraphData;
}

interface SimNode extends GraphNode {
  x: number;
  y: number;
  vx: number;
  vy: number;
  radius: number;
}

export const CorrelationGraphCanvas: React.FC<CorrelationGraphCanvasProps> = ({ data }) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [filterType, setFilterType] = useState<string>('ALL');

  const nodesRef = useRef<SimNode[]>([]);
  const linksRef = useRef<GraphLink[]>([]);
  const isDraggingRef = useRef<SimNode | null>(null);
  const animFrameRef = useRef<number | null>(null);

  useEffect(() => {
    // Initialize node positions in a radial layout
    const width = 800;
    const height = 500;
    const centerX = width / 2;
    const centerY = height / 2;

    const simNodes: SimNode[] = data.nodes.map((node, i) => {
      const angle = (i / Math.max(data.nodes.length, 1)) * 2 * Math.PI;
      const dist = node.type === 'EMAIL' ? 0 : node.type === 'CAMPAIGN' ? 220 : 130 + (i % 3) * 40;
      return {
        ...node,
        x: centerX + Math.cos(angle) * dist + (Math.random() - 0.5) * 20,
        y: centerY + Math.sin(angle) * dist + (Math.random() - 0.5) * 20,
        vx: 0,
        vy: 0,
        radius: node.type === 'EMAIL' ? 24 : node.type === 'CAMPAIGN' ? 20 : 16,
      };
    });

    nodesRef.current = simNodes;
    linksRef.current = data.links;

    // Run simple spring-embedder simulation
    let iteration = 0;
    const maxIterations = 240;

    const simulate = () => {
      const nodes = nodesRef.current;
      const links = linksRef.current;

      // Node repulsion (Coulomb's Law)
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const dx = nodes[j].x - nodes[i].x;
          const dy = nodes[j].y - nodes[i].y;
          const distSq = dx * dx + dy * dy || 1;
          const dist = Math.sqrt(distSq);
          if (dist < 220) {
            const force = (220 - dist) / dist * 0.4;
            nodes[i].vx -= dx * force * 0.05;
            nodes[i].vy -= dy * force * 0.05;
            nodes[j].vx += dx * force * 0.05;
            nodes[j].vy += dy * force * 0.05;
          }
        }
      }

      // Link attraction (Hooke's Law)
      links.forEach((link) => {
        const source = nodes.find((n) => n.id === link.source);
        const target = nodes.find((n) => n.id === link.target);
        if (source && target) {
          const dx = target.x - source.x;
          const dy = target.y - source.y;
          const dist = Math.sqrt(dx * dx + dy * dy) || 1;
          const desiredDist = 110;
          const force = (dist - desiredDist) * 0.03;
          source.vx += (dx / dist) * force;
          source.vy += (dy / dist) * force;
          target.vx -= (dx / dist) * force;
          target.vy -= (dy / dist) * force;
        }
      });

      // Gravity towards center & friction damping
      nodes.forEach((node) => {
        if (node !== isDraggingRef.current) {
          node.vx += (centerX - node.x) * 0.005;
          node.vy += (centerY - node.y) * 0.005;
          node.vx *= 0.85;
          node.vy *= 0.85;
          node.x += node.vx;
          node.y += node.vy;

          // Boundary constraint
          node.x = Math.max(30, Math.min(width - 30, node.x));
          node.y = Math.max(30, Math.min(height - 30, node.y));
        }
      });

      draw();

      iteration++;
      if (iteration < maxIterations || isDraggingRef.current) {
        animFrameRef.current = requestAnimationFrame(simulate);
      }
    };

    const draw = () => {
      const canvas = canvasRef.current;
      if (!canvas) return;
      const ctx = canvas.getContext('2d');
      if (!ctx) return;

      ctx.clearRect(0, 0, canvas.width, canvas.height);

      const nodes = nodesRef.current;
      const links = linksRef.current;

      // Draw Links
      links.forEach((link) => {
        const source = nodes.find((n) => n.id === link.source);
        const target = nodes.find((n) => n.id === link.target);
        if (!source || !target) return;

        ctx.beginPath();
        ctx.moveTo(source.x, source.y);
        ctx.lineTo(target.x, target.y);
        ctx.strokeStyle = link.relation === 'SEEN_IN_CAMPAIGN' ? 'rgba(244, 63, 94, 0.5)' : 'rgba(64, 64, 64, 0.7)';
        ctx.lineWidth = link.relation === 'SEEN_IN_CAMPAIGN' ? 2 : 1;
        ctx.stroke();

        // Draw edge label
        if (link.label) {
          const midX = (source.x + target.x) / 2;
          const midY = (source.y + target.y) / 2;
          ctx.fillStyle = '#737373';
          ctx.font = '9px JetBrains Mono, monospace';
          ctx.fillText(link.label, midX + 3, midY - 3);
        }
      });

      // Draw Nodes
      nodes.forEach((node) => {
        const isSelected = selectedNode?.id === node.id;

        // Node Color Logic
        let fillColor = '#0a0a0a';
        let strokeColor = '#818cf8';

        switch (node.type) {
          case 'EMAIL':
            strokeColor = node.risk === 'critical' ? '#f43f5e' : '#818cf8';
            break;
          case 'CAMPAIGN':
            strokeColor = '#e11d48';
            fillColor = '#881337';
            break;
          case 'IP':
            strokeColor = node.risk === 'critical' ? '#f43f5e' : '#f59e0b';
            break;
          case 'DOMAIN':
            strokeColor = node.risk === 'critical' ? '#f43f5e' : '#6366f1';
            break;
          case 'URL':
            strokeColor = '#ec4899';
            break;
          case 'ATTACHMENT_HASH':
            strokeColor = '#a855f7';
            break;
          case 'ASN':
            strokeColor = '#737373';
            break;
          case 'CASE':
            strokeColor = '#10b981';
            break;
        }

        // Draw Outer Glow for selected or critical
        if (isSelected || node.risk === 'critical') {
          ctx.beginPath();
          ctx.arc(node.x, node.y, node.radius + 6, 0, 2 * Math.PI);
          ctx.fillStyle = node.risk === 'critical' ? 'rgba(244, 63, 94, 0.25)' : 'rgba(99, 102, 241, 0.25)';
          ctx.fill();
        }

        // Draw Circle Node
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.radius, 0, 2 * Math.PI);
        ctx.fillStyle = fillColor;
        ctx.fill();
        ctx.lineWidth = isSelected ? 3 : 2;
        ctx.strokeStyle = strokeColor;
        ctx.stroke();

        // Node Type Icon Text
        ctx.fillStyle = strokeColor;
        ctx.font = 'bold 10px JetBrains Mono, monospace';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        const typeInitial = node.type.slice(0, 3);
        ctx.fillText(typeInitial, node.x, node.y);

        // Node Label below
        ctx.fillStyle = isSelected ? '#ffffff' : '#d4d4d4';
        ctx.font = isSelected ? 'bold 11px system-ui' : '10px system-ui';
        ctx.fillText(node.label, node.x, node.y + node.radius + 12);
      });
    };

    simulate();

    return () => {
      if (animFrameRef.current) cancelAnimationFrame(animFrameRef.current);
    };
  }, [data, selectedNode]);

  // Mouse interaction handlers
  const handleMouseDown = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const mouseX = e.clientX - rect.left;
    const mouseY = e.clientY - rect.top;

    const clicked = nodesRef.current.find((node) => {
      const dx = node.x - mouseX;
      const dy = node.y - mouseY;
      return Math.sqrt(dx * dx + dy * dy) <= node.radius + 6;
    });

    if (clicked) {
      isDraggingRef.current = clicked;
      setSelectedNode(clicked);
    } else {
      setSelectedNode(null);
    }
  };

  const handleMouseMove = (e: React.MouseEvent<HTMLCanvasElement>) => {
    if (!isDraggingRef.current) return;
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    isDraggingRef.current.x = e.clientX - rect.left;
    isDraggingRef.current.y = e.clientY - rect.top;
  };

  const handleMouseUp = () => {
    isDraggingRef.current = null;
  };

  return (
    <div className="space-y-4">
      
      {/* Top Controls & Campaign Notice */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-white flex items-center gap-2">
            <Share2 className="h-4 w-4 text-indigo-400" />
            Infrastructure & Threat Correlation Graph
          </h2>
          <p className="text-xs text-neutral-400">
            Interactive node-link graph correlating sender domains, relay IPs, ASNs, URLs, payload hashes, and campaign clusters.
          </p>
        </div>

        {data.campaign_name && (
          <div className="px-3 py-1.5 rounded-lg bg-rose-950/80 border border-rose-500/30 text-rose-300 text-xs font-mono flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-rose-400 animate-ping" />
            <span>{data.campaign_name}</span>
          </div>
        )}
      </div>

      {/* Canvas Area */}
      <div className="relative bg-neutral-950 border border-neutral-800 rounded-xl overflow-hidden shadow-2xl">
        <canvas
          ref={canvasRef}
          width={800}
          height={480}
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
          className="w-full h-[480px] cursor-grab active:cursor-grabbing"
        />

        {/* Selected Node Inspector Overlay */}
        {selectedNode && (
          <div className="absolute top-3 left-3 bg-neutral-900/95 backdrop-blur-md border border-indigo-500/40 rounded-xl p-4 max-w-sm text-xs font-mono space-y-2 shadow-2xl">
            <div className="flex items-center justify-between pb-1.5 border-b border-neutral-800">
              <span className="text-indigo-400 font-bold uppercase">{selectedNode.type} Node</span>
              <span className={`px-1.5 py-0.5 rounded text-[10px] uppercase ${
                selectedNode.risk === 'critical' ? 'bg-rose-500/20 text-rose-300' : 'bg-neutral-800 text-neutral-300'
              }`}>
                {selectedNode.risk} Risk
              </span>
            </div>
            <div className="text-white font-sans font-semibold text-sm break-all">{selectedNode.label}</div>
            {selectedNode.properties && (
              <div className="text-neutral-400 space-y-1 text-[11px] pt-1">
                {Object.entries(selectedNode.properties).map(([k, v]) => (
                  <div key={k} className="flex justify-between">
                    <span className="text-neutral-500">{k}:</span>
                    <span className="text-neutral-300 truncate max-w-[180px]">{String(v)}</span>
                  </div>
                ))}
              </div>
            )}
            <button
              onClick={() => setSelectedNode(null)}
              className="text-[10px] text-neutral-500 hover:text-neutral-300 underline pt-1 block cursor-pointer"
            >
              Close inspector
            </button>
          </div>
        )}

        {/* Legend */}
        <div className="absolute bottom-3 right-3 bg-neutral-900/90 backdrop-blur-md border border-neutral-800 rounded-lg p-2.5 text-[10px] font-mono grid grid-cols-2 gap-x-3 gap-y-1">
          <span className="text-indigo-400">● EMA (Email)</span>
          <span className="text-rose-400">● CAM (Campaign)</span>
          <span className="text-amber-400">● IP  (Network IP)</span>
          <span className="text-indigo-300">● DOM (Domain)</span>
          <span className="text-pink-400">● URL (Hyperlink)</span>
          <span className="text-purple-400">● HAS (Payload Hash)</span>
          <span className="text-emerald-400">● CAS (Case File)</span>
          <span className="text-neutral-400">● ASN (Autonomous Sys)</span>
        </div>
      </div>

    </div>
  );
};
