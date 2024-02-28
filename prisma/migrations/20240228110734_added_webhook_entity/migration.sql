/*
  Warnings:

  - Added the required column `value` to the `Sbom` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "Sbom" ADD COLUMN     "value" JSONB NOT NULL;

-- CreateTable
CREATE TABLE "Webhook" (
    "id" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "sbomNameInQuery" BOOLEAN NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Webhook_pkey" PRIMARY KEY ("id")
);
