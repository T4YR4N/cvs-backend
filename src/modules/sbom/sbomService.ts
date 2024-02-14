import { StatusCodes } from 'http-status-codes'

import { ResponseStatus, ServiceResponse } from '@common/models/serviceResponse'
import { Sbom } from '@modules/sbom/sbomModel'
import { sbomRepository } from '@modules/sbom/sbomRepository'
import { logger } from '@src/server'

export const sbomService = {
    // Retrieves all sboms from the database
    findAll: async (): Promise<ServiceResponse<Sbom[] | null>> => {
        try {
            const sboms = await sbomRepository.findAllAsync()
            if (!sboms) {
                return new ServiceResponse(ResponseStatus.Failed, 'No Sboms found', null, StatusCodes.NOT_FOUND)
            }
            return new ServiceResponse<Sbom[]>(ResponseStatus.Success, 'Sboms found', sboms, StatusCodes.OK)
        } catch (ex) {
            const errorMessage = `Error finding all sboms: $${(ex as Error).message}`
            logger.error(errorMessage)
            return new ServiceResponse(ResponseStatus.Failed, errorMessage, null, StatusCodes.INTERNAL_SERVER_ERROR)
        }
    },

    // Retrieves a single sbom by its ID
    findById: async (id: string): Promise<ServiceResponse<Sbom | null>> => {
        try {
            const sbom = await sbomRepository.findByIdAsync(id)
            if (!sbom) {
                return new ServiceResponse(ResponseStatus.Failed, 'Sbom not found', null, StatusCodes.NOT_FOUND)
            }
            return new ServiceResponse<Sbom>(ResponseStatus.Success, 'Sbom found', sbom, StatusCodes.OK)
        } catch (ex) {
            const errorMessage = `Error finding sbom with id ${id}:, ${(ex as Error).message}`
            logger.error(errorMessage)
            return new ServiceResponse(ResponseStatus.Failed, errorMessage, null, StatusCodes.INTERNAL_SERVER_ERROR)
        }
    },
}
