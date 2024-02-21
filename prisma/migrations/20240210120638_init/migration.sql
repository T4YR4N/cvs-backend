-- CreateTable
CREATE TABLE "Sbom" (
    "id" TEXT NOT NULL,
    "prettyName" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Sbom_pkey" PRIMARY KEY ("id")
);
