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
import json
import time

import falcon
from scalecodec.base import ScaleBytes
from scalecodec.block import ExtrinsicsDecoder, ExtrinsicsBlock61181Decoder
from scalecodec.metadata import MetadataDecoder
from sqlalchemy import and_
from substrateinterface import SubstrateInterface, StorageFunctionNotFound

from app.models.data import Block, RuntimeStorage, Extrinsic, Log, Event, RuntimeEvent, BlockTotal
from app.resources.base import BaseResource
from app.settings import SUBSTRATE_RPC_URL, SUBSTRATE_METADATA_VERSION, TYPE_REGISTRY, SUBSTRATE_ADDRESS_TYPE
from app.tasks import balance_snapshot
from app.utils.ss58 import ss58_encode


class ExtractMetadataResource(BaseResource):

    def on_get(self, req, resp):

        if 'block_hash' in req.params:
            substrate = SubstrateInterface(SUBSTRATE_RPC_URL)
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

        substrate = SubstrateInterface(SUBSTRATE_RPC_URL)

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
        substrate = SubstrateInterface(SUBSTRATE_RPC_URL)

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
        substrate = SubstrateInterface(SUBSTRATE_RPC_URL)

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


class CreateSnapshotResource(BaseResource):

    def on_post(self, req, resp):
        task = balance_snapshot.delay(
            account_id=req.media.get('account_id'),
            block_start=req.media.get('block_start'),
            block_end=req.media.get('block_end'),
            block_ids=req.media.get('block_ids')
        )

        resp.media = {'result': 'Balance snapshop task started', 'task_id': task.id}


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
            module_id='session',
            name='Validators',
            spec_version=head.spec_version_id
        ).first()

        if storage_call:
            try:
                validators = substrate.get_runtime_state(
                    module="Session",
                    storage_function="Validators",
                    params=[],
                    block_hash=head_hash
                ).get('result', [])
            except StorageFunctionNotFound:
                validators = []

        storage_call = RuntimeStorage.query(self.session).filter_by(
            module_id='staking',
            name='ValidatorCount',
            spec_version=head.spec_version_id
        ).first()

        if storage_call:
            try:
                validator_count = substrate.get_runtime_state(
                    module="Staking",
                    storage_function="ValidatorCount",
                    params=[],
                    block_hash=head_hash
                ).get('result', 0)
            except StorageFunctionNotFound:
                validator_count = 0

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
        page = int(req.params.get('page') if req.params.get('page') else 1)
        pageSize = int(req.params.get('page_size') if req.params.get('page_size') else 20)

        # blocks = Block.query(self.session).order_by(Block.id.desc()).limit(pageSize).offset((page - 1) * pageSize).all()
        blocks = Block.latest_blocks(self.session, page, pageSize)
        resp.status = falcon.HTTP_200
        result = [{
            "block_num": blockData.id,
            "event_count": blockData.count_events,
            "extrinsics_count": blockData.count_extrinsics,
            "block_timestamp": blockData.datetime.strftime("%Y-%m-%d %H:%M:%S"),
            "block_hash": blockData.hash,
            "author": ss58_encode(blockData.author.replace('0x', '')) if blockData.author is not None else None,
            # "block_timestamp": time.mktime(blockData.datetime.timetuple()),
            "finalized": "1" if blockData.author is not None else None,
        } for blockData in blocks]

        count = Block.query(self.session).count()
        resp.media = {
            'status': 'success',
            'data': {'result': result, 'count': count}
        }


# 根据block_num或hash获取区块信息
class GetBlockInfoByKeyResource(BaseResource):
    def on_post(self, req, resp):
        blockHash = None
        if req.media.get('block_id'):
            substrate = SubstrateInterface(url=SUBSTRATE_RPC_URL, address_type=SUBSTRATE_ADDRESS_TYPE,
                                           type_registry_preset=TYPE_REGISTRY)
            blockHash = substrate.get_block_hash(req.media.get('block_id'))
        elif req.media.get('block_hash'):
            blockHash = req.media.get('block_hash')
        else:
            resp.status = falcon.HTTP_BAD_REQUEST
            resp.media = {'errors': ['Either blockHash or block_id should be supplied']}

        if blockHash:
            resp.status = falcon.HTTP_200
            block = Block.query(self.session).filter(Block.hash == blockHash).first()
            blockTotal = BlockTotal.query(self.session).filter(BlockTotal.id == block.id).first()
            author = ss58_encode(blockTotal.author.replace('0x', '')) if blockTotal is not None else None

            if block:
                blockInfo = {}
                blockInfo["timestamp"] = block.datetime.strftime("%Y-%m-%d %H:%M:%S")
                blockInfo["block_hash"] = block.hash
                blockInfo["block_id"] = block.id
                blockInfo["parent_id"] = block.id - 1 if block.id > 0 else 0
                blockInfo["child_id"] = block.id + 1
                blockInfo["parent_hash"] = block.parent_hash
                blockInfo["state_root"] = block.state_root
                blockInfo["extrinsic_root"] = block.extrinsics_root
                blockInfo["validator"] = author
                blockInfo["count_extrinsic"] = block.count_extrinsics
                blockInfo["count_event"] = block.count_events
                blockInfo["count_log"] = block.count_log
                # blockInfo["age"] = time.mktime(block.datetime.timetuple())
                blockInfo["age"] = block.datetime.strftime("%Y-%m-%d %H:%M:%S")

                # 获取和区块相关的交易信息
                extrinsics = Extrinsic.query(self.session).filter(Extrinsic.block_id == block.id).all()
                extrinsicsObj = [{
                    "extrinsic_id": '{}-{}'.format(block.id, extrinsic.extrinsic_idx),
                    "hash": extrinsic.extrinsic_hash if extrinsic.extrinsic_hash else None,
                    # "age": time.mktime(block.datetime.timetuple()),
                    "age": block.datetime.strftime("%Y-%m-%d %H:%M:%S"),
                    "result": extrinsic.success,
                    # "address": extrinsic.address if extrinsic.address else None,
                    # "module": extrinsic.module_id,
                    # "fee": None,
                    # "nonce": extrinsic.nonce if extrinsic.nonce else None,
                    # "call": extrinsic.call_id,
                    "operation": '{}({})'.format(extrinsic.module_id, extrinsic.call_id),
                    "params": extrinsic.params
                    # "signature": extrinsic.signature if extrinsic.signature else None
                } for extrinsic in extrinsics]

                # 获取和区块相关的日志信息
                logs = Log.query(self.session).filter(Log.block_id == block.id).all()
                logsObj = [{
                    "log_id": '{}-{}'.format(block.id, log.log_idx),
                    "block_id": block.id,
                    "type": log.type,
                    "data": log.data['value']
                } for log in logs]

                # 获取和区块相关的事件信息
                events = Event.query(self.session).filter(Event.block_id == block.id).all()
                eventObj = [{
                    "id": '{}-{}'.format(block.id, event.event_idx),
                    "block_id": block.id,
                    "block_hash": block.hash,
                    "module_id": event.module_id,
                    "event_id": event.event_id,
                    "attributes": event.attributes,
                    "operation": '{}({})'.format(event.module_id, event.event_id),
                    "desc": self.getEventDesc(event.module_id, event.event_id),
                    "hash": self.getEventHash(block.id, event.extrinsic_idx)
                } for event in events]

                resp.media = {
                    'status': 'success',
                    'data': {
                        "block_info": blockInfo,
                        "extrinsics": extrinsicsObj,
                        "logs": logsObj,
                        "events": eventObj
                    }
                }
        else:
            resp.status = falcon.HTTP_404
            resp.media = {'result': 'Block not found'}

    def getEventDesc(self, moduleId, eventId):
        runtimeEvent = RuntimeEvent.query(self.session).filter(
            and_(RuntimeEvent.module_id == moduleId, RuntimeEvent.event_id == eventId)).first()
        if runtimeEvent:
            return runtimeEvent.documentation
        return ""

    def getEventHash(self, blockId, extrinsicIdx):
        extrinsic = Extrinsic.query(self.session).filter(
            and_(Extrinsic.block_id == blockId, Extrinsic.extrinsic_idx == extrinsicIdx)).first()
        if extrinsic:
            return extrinsic.extrinsic_hash
        return None


# 查询最近的转账交易
class LatestTransfersResource(BaseResource):
    def on_get(self, req, resp):
        resp.status = falcon.HTTP_200

        page = int(req.params.get('page') if req.params.get('page') else 1)
        pageSize = int(req.params.get('page_size') if req.params.get('page_size') else 10)
        extrinsics = Extrinsic.latest_extrinsics(self.session, page, pageSize)

        result = []
        for extrinsic in extrinsics:
            fromAddr = ss58_encode(extrinsic.address.replace('0x', ''))
            hash = "0x{}".format(extrinsic.extrinsic_hash)
            timestamp = extrinsic.datetime.strftime("%Y-%m-%d %H:%M:%S")
            # print(extrinsic);
            # timestamp = time.mktime(extrinsic.datetime.timetuple())

            params = json.loads(extrinsic.params)
            for param in params:
                name = param.get('name')
                if name == 'dest':
                    toAddr = ss58_encode(param.get('value').replace('0x', ''))
                elif name == 'value':
                    coin = param.get('value') / 1000000  # 转换为单位 micro

            result.append({
                "from": fromAddr,
                "to": toAddr,
                "hash": hash,
                "timestamp": timestamp,
                "coin": coin
            })

        resp.media = {
            'status': 'success',
            'data': result
        }
        # extrinsics = Extrinsic.query(self.session).filter(
        #     and_(Extrinsic.module_id == 'balances', Extrinsic.call_id == 'transfer')).order_by(
        #     Extrinsic.block_id.desc()).limit(20).all()
        #
        # results = []
        # extrinsicDict = dict()
        # for extrinsic in extrinsics:
        #     if not extrinsicDict.has_key(extrinsic.block_id):
        #         extrinsicDict
        #
        #     fromAddr = ss58_encode(extrinsic.address.replace('0x', ''))
        #     # extrinsicHash = '0x{}'.format(extrinsic.extrinsic_hash)
        #     extrinsicHash = '0x{}'.format(ss58_encode(extrinsic.extrinsic_hash))

        # substrate = SubstrateInterface(url=SUBSTRATE_RPC_URL, address_type=42,
        #                                type_registry_preset='default')
        # json_block = substrate.get_chain_block('0x7ed27725ff31cb66944ef25c3ddd79a2fc87050af05e381abda74e117ec4b2f8')
        # extrinsics_data = json_block['block'].pop('extrinsics')
        # result = []
        # metadata = substrate.get_block_metadata(
        #     block_hash='0x7ed27725ff31cb66944ef25c3ddd79a2fc87050af05e381abda74e117ec4b2f8')
        #
        # times = ''
        # for extrinsic in extrinsics_data:
        #     extrinsics_decoder = ExtrinsicsDecoder(
        #         data=ScaleBytes(extrinsic),
        #         metadata=metadata
        #     )
        #
        #     extrinsic_data = extrinsics_decoder.decode()
        #     if extrinsic_data['call_module'] == 'timestamp':
        #         value = extrinsic_data['params'][0].get('value')
        #         utc = dateutil.parser.parse(value).utcnow()
        #         times = utc.replace(tzinfo=pytz.utc).astimezone(pytz.timezone('Asia/Shanghai'))
        #
        #     result.append(extrinsic_data)
        #
        # accountId = '0x7ed27725ff31cb66944ef25c3ddd79a2fc87050af05e381abda74e117ec4b2f8'
        # accountAddress = ss58_encode(accountId.replace('0x', ''), 42)
        # resp.media = {
        #     'status': 'success',
        #     'data': result,
        #     'address': accountAddress,
        #     'time': times.strftime("%Y%m%d%H")
        # }

# 获取所有交易信息
class AllExtrinsicsResource(BaseResource):
    def on_get(self, req, resp):
        page = int(req.params.get('page') if req.params.get('page') else 1)
        pageSize = int(req.params.get('page_size') if req.params.get('page_size') else 10)

        resp.status = falcon.HTTP_200
        extrinsics = Extrinsic.all_extrinsics(self.session, page, pageSize)

        result = [{
            "extrinsic_id": '{}-{}'.format(extrinsic.block_id, extrinsic.extrinsic_idx),
            "hash": "0x{}".format(extrinsic.extrinsic_hash) if extrinsic.extrinsic_hash else None,
            "age": extrinsic.datetime.strftime("%Y-%m-%d %H:%M:%S"),
            "result": extrinsic.success,
            "operation": '{}({})'.format(extrinsic.module_id, extrinsic.call_id),
            "params": extrinsic.params,
            "address": extrinsic.address if extrinsic.address else None,
            "nonce": extrinsic.nonce if extrinsic.nonce else None,
            "signature": extrinsic.signature if extrinsic.signature else None
        } for extrinsic in extrinsics]

        count = Extrinsic.query(self.session).count()
        resp.media = {
            'status': 'success',
            'data': {'result': result, 'count': count}
        }

# 查询Block metadata信息
class BlockMetadataInfo(BaseResource):
    def on_post(self, req, resp):
        blockHash = None
        substrate = SubstrateInterface(SUBSTRATE_RPC_URL)
        if req.media.get('block_id'):
            blockHash = substrate.get_block_hash(req.media.get('block_id'))
        elif req.media.get('block_hash'):
            blockHash = req.media.get('block_hash')
        else:
            resp.status = falcon.HTTP_BAD_REQUEST
            resp.media = {'errors': ['Either blockHash or block_id should be supplied']}

        metadata = substrate.get_block_metadata(blockHash)

        resp.media = {
            'status': 'success',
            'data': metadata
        }