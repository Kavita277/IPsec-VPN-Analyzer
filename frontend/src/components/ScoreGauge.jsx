import React from "react";

export default function ScoreGauge({ score, rating, highestSeverity }) {
  const numericScore = typeof score === "number" ? Math.max(0, Math.min(100, score)) : null;

  // Circle dimensions
  const size = 150;
  const strokeWidth = 12;
  const center = size / 2;
  const radius = center - strokeWidth - 4;
  const circumference = 2 * Math.PI * radius;

  // Animate arc: 0 to 100% of circumference
  const strokeDashoffset = numericScore !== null
    ? circumference - (numericScore / 100) * circumference
    : circumference;

  // Determine semantic color for gauge stroke
  let strokeColor = "#F4D65E"; // Crextio warm yellow default
  if (highestSeverity === "Critical" || highestSeverity === "High") {
    strokeColor = "#D94E34"; // Coral / orange-red
  } else if (highestSeverity === "Medium") {
    strokeColor = "#E58B24"; // Warm amber
  } else if (highestSeverity === "Low") {
    strokeColor = "#2D72D2"; // Blue
  } else if (rating === "Compliant") {
    strokeColor = "#2E8540"; // Restrained green
  }

  return (
    <div className="score-gauge-wrap">
      <div className="score-gauge-chart" style={{ width: size, height: size }}>
        <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
          {/* Subtle decorative tick circle */}
          <circle
            cx={center}
            cy={center}
            r={radius + 8}
            fill="none"
            stroke="#E4E0D5"
            strokeWidth="1"
            strokeDasharray="2 6"
          />

          {/* Background track */}
          <circle
            cx={center}
            cy={center}
            r={radius}
            fill="none"
            stroke="rgba(41, 41, 41, 0.08)"
            strokeWidth={strokeWidth}
          />

          {/* Foreground progress arc */}
          {numericScore !== null && (
            <circle
              cx={center}
              cy={center}
              r={radius}
              fill="none"
              stroke={strokeColor}
              strokeWidth={strokeWidth}
              strokeDasharray={circumference}
              strokeDashoffset={strokeDashoffset}
              strokeLinecap="round"
              transform={`rotate(-90 ${center} ${center})`}
              className="gauge-arc"
            />
          )}
        </svg>

        <div className="score-gauge-center">
          <span className="score-gauge-val">
            {numericScore !== null ? numericScore : "N/A"}
          </span>
          <span className="score-gauge-max">/ 100</span>
        </div>
      </div>

      <div className="score-gauge-meta">
        <div className={`score-badge sev-${highestSeverity || "None"}`}>
          <span className="score-badge-dot" style={{ background: strokeColor }} />
          <span>{rating || "Pending"}</span>
        </div>
        <p className="score-gauge-desc">
          {numericScore !== null
            ? "100 base minus weighted policy penalties"
            : "No parameters extracted to score"}
        </p>
      </div>
    </div>
  );
}
