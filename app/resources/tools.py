#  Polkascan PRE Harvester
#
#  Copyright 2018-2020 openAware BV (NL).
#  This file is part of Polkascan.
#
#  Polkascan is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  Polkascan is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with Polkascan. If not, see <http://www.gnu.org/licenses/>.
#
#  tools.py
import time
from datetime import datetime

import falcon
from scalecodec.exceptions import RemainingScaleBytesNotEmptyException
from sqlalchemy import and_

from app.models.data import Block, Session, RuntimeStorage, Extrinsic
from app.resources.base import BaseResource

from scalecodec.base import ScaleBytes
from scalecodec.metadata import MetadataDecoder
from scalecodec.block import EventsDecoder, ExtrinsicsDecoder, ExtrinsicsBlock61181Decoder

from substrateinterface import SubstrateInterface
from app.settings import SUBSTRATE_RPC_URL, SUBSTRATE_METADATA_VERSION, TYPE_REGISTRY, SUBSTRATE_ADDRESS_TYPE
from app.utils.ss58 import ss58_encode


class ExtractMetadataResource(BaseResource):

    def on_get(self, req, resp):

        if 'block_hash' in req.params:
            substrate = SubstrateInterface(url=SUBSTRATE_RPC_URL, address_type=SUBSTRATE_ADDRESS_TYPE,
                                           type_registry_preset=TYPE_REGISTRY)
            metadata = substrate.get_block_metadata(req.params.get('block_hash'))

            resp.status = falcon.HTTP_200
            resp.media = metadata.value
        else:
            resp.status = falcon.HTTP_BAD_REQUEST

    def on_post(self, req, resp):
        metadata = MetadataDecoder(ScaleBytes(req.media.get('result')))

        resp.status = falcon.HTTP_200
        resp.media = metadata.process()


class ExtractExtrinsicsResource(BaseResource):

    def on_get(self, req, resp):

        substrate = SubstrateInterface(url=SUBSTRATE_RPC_URL, address_type=SUBSTRATE_ADDRESS_TYPE,
                                       type_registry_preset=TYPE_REGISTRY)

        # Get extrinsics
        json_block = substrate.get_chain_block(req.params.get('block_hash'))

        if not json_block:
            resp.status = falcon.HTTP_404
        else:

            extrinsics = json_block['block']['extrinsics']

            # Get metadata
            metadata_decoder = substrate.get_block_metadata(json_block['block']['header']['parentHash'])

            # result = [{'runtime': substrate.get_block_runtime_version(req.params.get('block_hash')), 'metadata': metadata_result.get_data_dict()}]
            result = []

            for extrinsic in extrinsics:
                if int(json_block['block']['header']['number'], 16) == 61181:
                    extrinsics_decoder = ExtrinsicsBlock61181Decoder(ScaleBytes(extrinsic), metadata=metadata_decoder)
                else:
                    extrinsics_decoder = ExtrinsicsDecoder(ScaleBytes(extrinsic), metadata=metadata_decoder)
                result.append(extrinsics_decoder.decode())

            resp.status = falcon.HTTP_201
            resp.media = result


class ExtractEventsResource(BaseResource):

    def on_get(self, req, resp):
        substrate = SubstrateInterface(url=SUBSTRATE_RPC_URL, address_type=SUBSTRATE_ADDRESS_TYPE,
                                       type_registry_preset=TYPE_REGISTRY)

        # Get Parent hash
        json_block = substrate.get_block_header(req.params.get('block_hash'))

        # Get metadata
        metadata_decoder = substrate.get_block_metadata(json_block['parentHash'])

        # Get events for block hash
        events_decoder = substrate.get_block_events(req.params.get('block_hash'), metadata_decoder=metadata_decoder)

        resp.status = falcon.HTTP_201
        resp.media = {'events': events_decoder.value,
                      'runtime': substrate.get_block_runtime_version(req.params.get('block_hash'))}


class HealthCheckResource(BaseResource):
    def on_get(self, req, resp):
        resp.media = {'status': 'OK'}


class StorageValidatorResource(BaseResource):

    def on_get(self, req, resp):
        substrate = SubstrateInterface(url=SUBSTRATE_RPC_URL, address_type=SUBSTRATE_ADDRESS_TYPE,
                                       type_registry_preset=TYPE_REGISTRY)

        resp.status = falcon.HTTP_200

        current_era = substrate.get_storage(
            block_hash="0x519fc882113d886615ad5c7a93f8319640270ab8a09546798f7f8d973a99b017",
            module="Staking",
            function="CurrentEra",
            return_scale_type='BlockNumber',
            metadata_version=SUBSTRATE_METADATA_VERSION
        )

        # Retrieve validator for new session from storage
        validators = substrate.get_storage(
            block_hash="0x519fc882113d886615ad5c7a93f8319640270ab8a09546798f7f8d973a99b017",
            module="Session",
            function="Validators",
            return_scale_type='Vec<AccountId>',
            metadata_version=SUBSTRATE_METADATA_VERSION
        ) or []

        # for validator in validators:
        #     storage_bytes = substrate.get_storage("0x904871d0e6284c0555134fa187891580979a2fc426a4f8873a8d15d8cca6020f",
        #                                           "Balances", "FreeBalance", validator.replace('0x', ''))
        #     #print(validator.replace('0x', ''))
        #
        #     if storage_bytes:
        #         obj = ScaleDecoder.get_decoder_class('Balance', ScaleBytes(storage_bytes))
        #         nominators.append(obj.decode())

        resp.media = {'validators': validators, 'current_era': current_era}


# 获取Metadata
class MetadataResource(BaseResource):
    def on_get(self, req, resp):
        substrate = SubstrateInterface(url=SUBSTRATE_RPC_URL, address_type=SUBSTRATE_ADDRESS_TYPE,
                                       type_registry_preset=TYPE_REGISTRY)
        resp.status = falcon.HTTP_200
        head = Block.get_head(self.session);
        head_hash = substrate.get_chain_head()
        head_number = substrate.get_block_number(head_hash)
        finalised_head_hash = substrate.get_chain_finalised_head()
        finalised_head_number = substrate.get_block_number(finalised_head_hash)

        extrinsicCount = Extrinsic.query(self.session).filter(Extrinsic.signed == 1).count()

        storage_call = RuntimeStorage.query(self.session).filter_by(
            module_id = 'session',
            name = 'Validators',
            spec_version = head.spec_version_id
        ).first()

        if storage_call:
            try:
                validators = substrate.get_storage(
                    block_hash=head.hash,
                    module="Session",
                    function="Validators",
                    return_scale_type=storage_call.get_return_type(),
                    metadata_version=SUBSTRATE_METADATA_VERSION
                ) or []
            except RemainingScaleBytesNotEmptyException:
                pass

        storage_call = RuntimeStorage.query(self.session).filter_by(
            module_id='staking',
            name='ValidatorCount',
            spec_version=head.spec_version_id
        ).first()

        if storage_call:
            try:
                validator_count = substrate.get_storage(
                    block_hash=head.hash,
                    module="Staking",
                    function="ValidatorCount",
                    return_scale_type=storage_call.get_return_type(),
                    metadata_version=SUBSTRATE_METADATA_VERSION
                ) or []
            except RemainingScaleBytesNotEmptyException:
                pass

        transfers_count = Extrinsic.query(self.session).filter(
            and_(Extrinsic.module_id == 'balances', Extrinsic.call_id == 'transfer')).count()

        resp.media = {
            'status': 'success',
            'data': {
                'blockNumber': head_number,
                'finalizedBlockNumber': finalised_head_number,
                'extrinsics': extrinsicCount,
                'currValidators': len(validators),
                'validators': validator_count,
                'transfersCount': transfers_count
            }
        }

# 获取最新区块列表，取20个
class LatestBlocksResource(BaseResource):
    def on_get(self, req, resp):
        blocks = Block.query(self.session).order_by(Block.id.desc()).limit(20).all();

        resp.status = falcon.HTTP_200
        result = [{
            "block_num": blockData.id,
            "event_count": blockData.count_events,
            "extrinsics_count": blockData.count_extrinsics,
            "block_timestamp": time.mktime(blockData.datetime.timetuple()),
            # "finalized": "1"
        } for blockData in blocks]

        resp.media = {
            'status': 'success',
            'data': result
        }

# 查询最近的转账交易
class LatestTransfersResource(BaseResource):
    def on_get(self, req, resp):
        resp.status = falcon.HTTP_200

        extrinsics = Extrinsic.query(self.session).filter(
            and_(Extrinsic.module_id == 'balances', Extrinsic.call_id == 'transfer')).order_by(
            Extrinsic.block_id.desc()).limit(20).all()

        results = []
        extrinsicDict = dict()
        for extrinsic in extrinsics:
            if not extrinsicDict.has_key(extrinsic.block_id):
                extrinsicDict

            fromAddr = ss58_encode(extrinsic.address.replace('0x', ''))
            # extrinsicHash = '0x{}'.format(extrinsic.extrinsic_hash)
            extrinsicHash = '0x{}'.format(ss58_encode(extrinsic.extrinsic_hash))


        # substrate = SubstrateInterface(url=SUBSTRATE_RPC_URL, address_type=42,
        #                                type_registry_preset='default')
        # json_block = substrate.get_chain_block('0x6e33c5c93609cc271dc31b61f254f99760a8191fa28bc0f40c4edc6e9250a95d')
        # extrinsics_data = json_block['block'].pop('extrinsics')
        # result = []
        # metadata = substrate.get_block_metadata(
        #     block_hash='0x6e33c5c93609cc271dc31b61f254f99760a8191fa28bc0f40c4edc6e9250a95d')
        #
        # for extrinsic in extrinsics_data:
        #     extrinsics_decoder = ExtrinsicsDecoder(
        #         data=ScaleBytes(extrinsic),
        #         metadata=metadata
        #     )
        #
        #     extrinsic_data = extrinsics_decoder.decode()
        #     result.append(extrinsic_data)
        #
        # accountId = '0x8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48'
        # accountAddress = ss58_encode(accountId.replace('0x', ''), 42)
        resp.media = {
            'status': 'success',
            'data': result,
            'address': accountAddress
        }
