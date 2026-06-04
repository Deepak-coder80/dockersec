package dockerfile

import (
	"github.com/Deepak-coder80/dockersec/internal/models"
	"github.com/Deepak-coder80/dockersec/internal/parser"
	"github.com/Deepak-coder80/dockersec/internal/rules"
)

func init() {
	rules.RegisterDockerfileRule(checkMultiStage)
}

func checkMultiStage(df *parser.ParsedDockerfile) []models.Finding {
	fromInstructions := df.FindAllInstructions("FROM")

	if len(fromInstructions) < 2 {
		return []models.Finding{
			{
				RuleID:   "DF011",
				Severity: models.SeverityMedium,
				Description: "Single-stage build detected. Multi-stage builds are a Docker best practice for production images. " +
					"In a single-stage build, your final image contains everything: build tools, compilers, temp files, and source code. " +
					"This bloats image size and increases your attack surface. Multi-stage builds let you compile in one stage " +
					"and copy only the final artifact into a clean minimal image.",
				Line: 1,
				Fix: "Split your Dockerfile into a builder stage and a final stage. Example:\n" +
					"  FROM node:20 AS builder\n" +
					"  WORKDIR /app\n" +
					"  COPY . .\n" +
					"  RUN npm ci --production\n\n" +
					"  FROM node:20-alpine\n" +
					"  COPY --from=builder /app/dist /app\n" +
					"  CMD [\"node\", \"/app/index.js\"]",
			},
		}
	}

	return nil
}
