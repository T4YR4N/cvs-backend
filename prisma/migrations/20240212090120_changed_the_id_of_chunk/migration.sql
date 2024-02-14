/*
  Warnings:

  - The primary key for the `Chunk` table will be changed. If it partially fails, the table could be left without primary key constraint.
  - You are about to drop the column `matchId` on the `Chunk` table. All the data in the column will be lost.
  - Added the required column `detailsHash` to the `Chunk` table without a default value. This is not possible if the table is not empty.

*/
-- DropForeignKey
ALTER TABLE "Chunk" DROP CONSTRAINT "Chunk_matchId_vulnId_artifactId_fkey";

-- AlterTable
ALTER TABLE "Chunk" DROP CONSTRAINT "Chunk_pkey",
DROP COLUMN "matchId",
ADD COLUMN     "detailsHash" TEXT NOT NULL,
ADD CONSTRAINT "Chunk_pkey" PRIMARY KEY ("scanId", "detailsHash", "vulnId", "artifactId");

-- AddForeignKey
ALTER TABLE "Chunk" ADD CONSTRAINT "Chunk_detailsHash_vulnId_artifactId_fkey" FOREIGN KEY ("detailsHash", "vulnId", "artifactId") REFERENCES "Match"("detailsHash", "vulnId", "artifactId") ON DELETE RESTRICT ON UPDATE CASCADE;
