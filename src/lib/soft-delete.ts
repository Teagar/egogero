export interface SoftDeleteQueryOptions<
  Where extends object,
  WhereUnique extends object,
  OrderBy extends object,
  ScalarField
> {
  // Relations are queried through their own repository so they receive the same active filter.
  where?: Where;
  orderBy?: OrderBy | OrderBy[];
  cursor?: WhereUnique;
  skip?: number;
  take?: number;
  distinct?: ScalarField | ScalarField[];
}

interface SoftDeleteDelegate<
  Entity,
  Where extends object,
  WhereUnique extends object,
  OrderBy extends object,
  ScalarField,
  BatchPayload
> {
  findMany(
    args: SoftDeleteQueryOptions<Where, WhereUnique, OrderBy, ScalarField> & { where: Where }
  ): PromiseLike<Entity[]>;
  findFirst(
    args: SoftDeleteQueryOptions<Where, WhereUnique, OrderBy, ScalarField> & { where: Where }
  ): PromiseLike<Entity | null>;
  findUnique(args: { where: WhereUnique }): PromiseLike<Entity | null>;
  update(args: { where: WhereUnique; data: { deletedAt: Date } }): PromiseLike<Entity>;
  updateMany(args: { where: Where; data: { deletedAt: Date } }): PromiseLike<BatchPayload>;
}

function activeWhere<Where extends object>(where?: object): Where {
  return { ...where, deletedAt: null } as Where;
}

export function createSoftDeleteRepository<
  Entity,
  Where extends object,
  WhereUnique extends object,
  OrderBy extends object,
  ScalarField,
  BatchPayload
>(
  delegate: SoftDeleteDelegate<
    Entity,
    Where,
    WhereUnique,
    OrderBy,
    ScalarField,
    BatchPayload
  >,
  now: () => Date = () => new Date()
) {
  type QueryOptions = SoftDeleteQueryOptions<Where, WhereUnique, OrderBy, ScalarField>;

  return {
    findMany(args: QueryOptions = {}) {
      return delegate.findMany({ ...args, where: activeWhere(args.where) });
    },

    findFirst(args: QueryOptions = {}) {
      return delegate.findFirst({ ...args, where: activeWhere(args.where) });
    },

    findUnique(where: WhereUnique) {
      return delegate.findFirst({ where: activeWhere(where) });
    },

    findUniqueIncludingDeleted(where: WhereUnique) {
      return delegate.findUnique({ where });
    },

    delete(where: WhereUnique) {
      return delegate.update({
        where: activeWhere(where),
        data: { deletedAt: now() }
      });
    },

    deleteMany(where?: Where) {
      return delegate.updateMany({
        where: activeWhere(where),
        data: { deletedAt: now() }
      });
    }
  };
}
