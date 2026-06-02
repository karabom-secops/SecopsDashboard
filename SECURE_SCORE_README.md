# Secure Score Implementation

## Overview

A comprehensive security score (0-100) has been implemented for the SecopsDashboard. This composite score combines vulnerabilities, security awareness, and incident response metrics to provide a holistic view of organizational security posture.

## Score Composition

The Secure Score is calculated as a weighted average of three key components:

### 1. **Vulnerability Score** (Weight: 40%)
- **Calculation**: Based on the latest vulnerability scan data
- **Formula**: `100 - (critical×20 + high×10 + medium×5 + low×1)`
- **Capped**: Score ranges from 0 to 100
- **Interpretation**: 
  - 80+: Excellent - minimal critical/high findings
  - 70-79: Good - manageable risk level
  - 50-69: Fair - significant findings need attention
  - <50: Poor - critical remediation required

### 2. **Security Awareness Score** (Weight: 35%)
- **Calculation**: Based on training completion rates
- **Formula**: `(completed_users / total_users) × 100`
- **Data Source**: Latest security awareness CSV upload
- **Interpretation**: 
  - 90%+: Excellent engagement
  - 70-89%: Good participation
  - 50-69%: Fair, improvement needed
  - <50%: Poor, urgent action required

### 3. **MDR/Incident Response Score** (Weight: 25%)
- **Calculation**: Based on ticket resolution metrics
- **Formula**: `(resolved_tickets / total_tickets) × 100 - resolution_speed_penalty`
- **Speed Penalty**: Up to 20 points deducted if average resolution > 24 hours
- **Data Source**: Latest Arctic Wolf MDR ticket upload
- **Interpretation**:
  - 85%+: Excellent response capability
  - 70-84%: Good incident handling
  - 50-69%: Fair, needs improvement
  - <50%: Poor, process improvement needed

## API Endpoints

### Get Current Secure Score
```bash
GET /api/secure-score
```

**Response:**
```json
{
  "tenantId": 1,
  "score": 78,
  "rating": "Good",
  "components": {
    "vulnerabilities": { "score": 85, "weight": 0.40 },
    "awareness": { "score": 72, "weight": 0.35 },
    "incidentResponse": { "score": 75, "weight": 0.25 }
  },
  "dataAge": {
    "vulns": "2024-05-15",
    "awareness": "2024-06-01T10:30:00Z",
    "mdr": "2024-06-01T09:15:00Z"
  },
  "recommendations": [
    {
      "priority": "medium",
      "area": "Vulnerabilities",
      "suggestion": "Address remaining high-severity findings...",
      "impact": "Moderate"
    }
  ]
}
```

### Get Historical Score Trend
```bash
GET /api/secure-score/history
```

**Response:**
```json
{
  "tenantId": 1,
  "history": [
    { "monthKey": "2024-04", "score": 72 },
    { "monthKey": "2024-05", "score": 75 },
    { "monthKey": "2024-06", "score": 78 }
  ]
}
```

## UI Components

### New Tab: "Security Posture"
- Located in the main navigation sidebar
- Accessible to all authenticated users
- Shows per-tenant security scores

### Dashboard Displays
1. **Main Score Gauge**: Large circular display (0-100) with color coding
   - Green (80+): Excellent
   - Orange (70-79): Good
   - Dark Orange (50-69): Fair
   - Red (<50): Poor

2. **Component Breakdown**: Three cards showing individual score contributions
   - Each card includes a progress bar and description
   - Weighted percentages displayed

3. **6-Month Trend Chart**: Visual representation of score progression
   - Helps identify trends and improvements over time

4. **Improvement Recommendations**: Prioritized action items
   - High-priority (red): Critical issues
   - Medium-priority (orange): Improvements needed
   - Info (green): Positive feedback

5. **Data Age Information**: Shows when each data source was last updated

## Database (Optional)

A migration file has been provided to create a `secure_scores` table for historical score tracking:

```bash
psql -U your_user -d your_db -f db/migrate-secure-scores.sql
```

This allows you to:
- Store daily/weekly score snapshots
- Track score trends over extended periods
- Generate audit trails
- Set up automated alerts for score drops

**Note**: The current implementation calculates scores on-the-fly from existing data, so this table is optional.

## Implementation Details

### Files Created/Modified

**New Files:**
- `lib/secure-score.js` - Scoring calculation engine
- `public/js/tab-secure-score.js` - Frontend tab implementation
- `public/css/secure-score.css` - Styling for the score display
- `db/migrate-secure-scores.sql` - Optional database schema

**Modified Files:**
- `server.js` - Added two new API endpoints
- `public/index.html` - Added tab button and tab panel
- `public/index.html` - Linked new CSS and JavaScript files

### Key Functions

#### Backend (`lib/secure-score.js`)
- `calculateVulnScore()` - Computes vulnerability component
- `calculateAwarenessScore()` - Computes awareness component
- `calculateMdrScore()` - Computes MDR component
- `calculateSecureScore()` - Main function combining all components
- `generateRecommendations()` - Creates actionable improvement suggestions

#### Frontend (`public/js/tab-secure-score.js`)
- `fetchSecureScore()` - Retrieves current score from API
- `fetchScoreHistory()` - Retrieves historical trend data
- `renderScoreGauge()` - Draws SVG circular gauge
- `renderComponentScores()` - Displays component breakdown
- `renderTrendChart()` - Draws trend chart
- `renderRecommendations()` - Shows improvement suggestions

## Auto-Refresh

The frontend automatically refreshes the score display every 5 minutes, ensuring data stays current without manual page reload.

## Multi-Tenant Support

The Secure Score is calculated per-tenant:
- Each organization sees only their own score
- Superadmins can view all tenant scores (future enhancement)
- Tenant switching automatically updates the displayed score

## Future Enhancements

1. **Daily Snapshots**: Store daily score in `secure_scores` table
2. **Alerts**: Notify admins if score drops below threshold
3. **Benchmarking**: Compare tenant score against industry average
4. **Export**: Generate PDF reports of score trends
5. **Weighted Customization**: Allow admins to adjust component weights
6. **Custom Metrics**: Add additional risk factors (e.g., compliance, SIEM events)

## Testing

To test the implementation:

1. Start the server: `npm start`
2. Upload vulnerability scan data (if not already present)
3. Upload security awareness training data
4. Upload Arctic Wolf MDR tickets
5. Navigate to "Security Posture" tab in the dashboard
6. Score should calculate and display automatically

## Support

For issues or questions:
- Check that all required data sources have uploads
- Verify API endpoints return valid responses: `/api/secure-score`
- Review browser console for JavaScript errors
- Check server logs for backend errors
